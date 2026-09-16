rule TTP_XOR_QUAD_CurrentVersionRun_3b68 {
  strings:
    $key_3b68 = { 68 07 [2] 4c 09 [2] 67 25 [2] 49 07 [2] 5d 1c [2] 52 06 [2] 4c 1b [2] 4e 1a [2] 55 1c [2] 49 1b [2] 55 34 }

  condition:
    any of them
}