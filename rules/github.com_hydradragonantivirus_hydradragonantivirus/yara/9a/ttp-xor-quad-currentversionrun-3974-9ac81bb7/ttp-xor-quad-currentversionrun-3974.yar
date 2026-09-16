rule TTP_XOR_QUAD_CurrentVersionRun_3974 {
  strings:
    $key_3974 = { 6a 1b [2] 4e 15 [2] 65 39 [2] 4b 1b [2] 5f 00 [2] 50 1a [2] 4e 07 [2] 4c 06 [2] 57 00 [2] 4b 07 [2] 57 28 }

  condition:
    any of them
}