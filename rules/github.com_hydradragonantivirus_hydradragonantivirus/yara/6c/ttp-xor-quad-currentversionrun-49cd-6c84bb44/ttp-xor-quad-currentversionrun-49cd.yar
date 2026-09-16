rule TTP_XOR_QUAD_CurrentVersionRun_49cd {
  strings:
    $key_49cd = { 1a a2 [2] 3e ac [2] 15 80 [2] 3b a2 [2] 2f b9 [2] 20 a3 [2] 3e be [2] 3c bf [2] 27 b9 [2] 3b be [2] 27 91 }

  condition:
    any of them
}