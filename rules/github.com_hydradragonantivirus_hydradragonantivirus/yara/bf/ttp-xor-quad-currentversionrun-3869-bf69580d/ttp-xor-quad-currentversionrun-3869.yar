rule TTP_XOR_QUAD_CurrentVersionRun_3869 {
  strings:
    $key_3869 = { 6b 06 [2] 4f 08 [2] 64 24 [2] 4a 06 [2] 5e 1d [2] 51 07 [2] 4f 1a [2] 4d 1b [2] 56 1d [2] 4a 1a [2] 56 35 }

  condition:
    any of them
}