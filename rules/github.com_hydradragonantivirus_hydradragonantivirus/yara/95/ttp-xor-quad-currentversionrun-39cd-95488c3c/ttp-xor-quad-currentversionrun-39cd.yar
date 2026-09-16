rule TTP_XOR_QUAD_CurrentVersionRun_39cd {
  strings:
    $key_39cd = { 6a a2 [2] 4e ac [2] 65 80 [2] 4b a2 [2] 5f b9 [2] 50 a3 [2] 4e be [2] 4c bf [2] 57 b9 [2] 4b be [2] 57 91 }

  condition:
    any of them
}