rule TTP_XOR_QUAD_CurrentVersionRun_6a68 {
  strings:
    $key_6a68 = { 39 07 [2] 1d 09 [2] 36 25 [2] 18 07 [2] 0c 1c [2] 03 06 [2] 1d 1b [2] 1f 1a [2] 04 1c [2] 18 1b [2] 04 34 }

  condition:
    any of them
}