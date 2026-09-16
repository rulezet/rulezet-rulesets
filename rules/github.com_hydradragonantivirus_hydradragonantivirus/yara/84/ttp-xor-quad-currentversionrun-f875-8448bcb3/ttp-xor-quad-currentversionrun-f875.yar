rule TTP_XOR_QUAD_CurrentVersionRun_f875 {
  strings:
    $key_f875 = { ab 1a [2] 8f 14 [2] a4 38 [2] 8a 1a [2] 9e 01 [2] 91 1b [2] 8f 06 [2] 8d 07 [2] 96 01 [2] 8a 06 [2] 96 29 }

  condition:
    any of them
}