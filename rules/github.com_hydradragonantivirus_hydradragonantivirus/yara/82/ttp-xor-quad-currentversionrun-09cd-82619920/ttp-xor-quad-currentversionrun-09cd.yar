rule TTP_XOR_QUAD_CurrentVersionRun_09cd {
  strings:
    $key_09cd = { 5a a2 [2] 7e ac [2] 55 80 [2] 7b a2 [2] 6f b9 [2] 60 a3 [2] 7e be [2] 7c bf [2] 67 b9 [2] 7b be [2] 67 91 }

  condition:
    any of them
}