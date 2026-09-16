rule TTP_XOR_QUAD_CurrentVersionRun_e9cd {
  strings:
    $key_e9cd = { ba a2 [2] 9e ac [2] b5 80 [2] 9b a2 [2] 8f b9 [2] 80 a3 [2] 9e be [2] 9c bf [2] 87 b9 [2] 9b be [2] 87 91 }

  condition:
    any of them
}