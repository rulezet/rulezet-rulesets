rule TTP_XOR_QUAD_CurrentVersionRun_69cd {
  strings:
    $key_69cd = { 3a a2 [2] 1e ac [2] 35 80 [2] 1b a2 [2] 0f b9 [2] 00 a3 [2] 1e be [2] 1c bf [2] 07 b9 [2] 1b be [2] 07 91 }

  condition:
    any of them
}