rule TTP_XOR_QUAD_CurrentVersionRun_3a66 {
  strings:
    $key_3a66 = { 69 09 [2] 4d 07 [2] 66 2b [2] 48 09 [2] 5c 12 [2] 53 08 [2] 4d 15 [2] 4f 14 [2] 54 12 [2] 48 15 [2] 54 3a }

  condition:
    any of them
}