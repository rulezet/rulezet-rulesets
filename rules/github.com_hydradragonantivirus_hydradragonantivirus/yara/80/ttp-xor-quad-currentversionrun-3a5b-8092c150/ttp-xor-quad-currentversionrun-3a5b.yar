rule TTP_XOR_QUAD_CurrentVersionRun_3a5b {
  strings:
    $key_3a5b = { 69 34 [2] 4d 3a [2] 66 16 [2] 48 34 [2] 5c 2f [2] 53 35 [2] 4d 28 [2] 4f 29 [2] 54 2f [2] 48 28 [2] 54 07 }

  condition:
    any of them
}