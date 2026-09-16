rule TTP_XOR_QUAD_CurrentVersionRun_6b66 {
  strings:
    $key_6b66 = { 38 09 [2] 1c 07 [2] 37 2b [2] 19 09 [2] 0d 12 [2] 02 08 [2] 1c 15 [2] 1e 14 [2] 05 12 [2] 19 15 [2] 05 3a }

  condition:
    any of them
}