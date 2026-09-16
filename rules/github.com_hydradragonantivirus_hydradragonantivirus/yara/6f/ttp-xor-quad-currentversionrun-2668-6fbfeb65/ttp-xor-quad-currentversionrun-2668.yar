rule TTP_XOR_QUAD_CurrentVersionRun_2668 {
  strings:
    $key_2668 = { 75 07 [2] 51 09 [2] 7a 25 [2] 54 07 [2] 40 1c [2] 4f 06 [2] 51 1b [2] 53 1a [2] 48 1c [2] 54 1b [2] 48 34 }

  condition:
    any of them
}