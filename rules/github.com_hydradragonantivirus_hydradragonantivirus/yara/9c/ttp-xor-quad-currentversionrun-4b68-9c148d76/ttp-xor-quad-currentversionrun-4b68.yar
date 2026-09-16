rule TTP_XOR_QUAD_CurrentVersionRun_4b68 {
  strings:
    $key_4b68 = { 18 07 [2] 3c 09 [2] 17 25 [2] 39 07 [2] 2d 1c [2] 22 06 [2] 3c 1b [2] 3e 1a [2] 25 1c [2] 39 1b [2] 25 34 }

  condition:
    any of them
}