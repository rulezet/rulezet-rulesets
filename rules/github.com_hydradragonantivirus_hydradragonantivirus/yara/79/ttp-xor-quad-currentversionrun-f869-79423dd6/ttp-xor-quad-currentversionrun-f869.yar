rule TTP_XOR_QUAD_CurrentVersionRun_f869 {
  strings:
    $key_f869 = { ab 06 [2] 8f 08 [2] a4 24 [2] 8a 06 [2] 9e 1d [2] 91 07 [2] 8f 1a [2] 8d 1b [2] 96 1d [2] 8a 1a [2] 96 35 }

  condition:
    any of them
}