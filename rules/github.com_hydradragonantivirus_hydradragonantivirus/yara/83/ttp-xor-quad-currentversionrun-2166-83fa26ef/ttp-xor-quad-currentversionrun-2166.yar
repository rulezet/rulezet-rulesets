rule TTP_XOR_QUAD_CurrentVersionRun_2166 {
  strings:
    $key_2166 = { 72 09 [2] 56 07 [2] 7d 2b [2] 53 09 [2] 47 12 [2] 48 08 [2] 56 15 [2] 54 14 [2] 4f 12 [2] 53 15 [2] 4f 3a }

  condition:
    any of them
}