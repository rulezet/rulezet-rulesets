rule TTP_XOR_QUAD_CurrentVersionRun_1b68 {
  strings:
    $key_1b68 = { 48 07 [2] 6c 09 [2] 47 25 [2] 69 07 [2] 7d 1c [2] 72 06 [2] 6c 1b [2] 6e 1a [2] 75 1c [2] 69 1b [2] 75 34 }

  condition:
    any of them
}