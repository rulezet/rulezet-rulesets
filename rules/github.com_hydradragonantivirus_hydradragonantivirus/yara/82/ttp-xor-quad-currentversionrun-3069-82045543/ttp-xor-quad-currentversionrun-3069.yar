rule TTP_XOR_QUAD_CurrentVersionRun_3069 {
  strings:
    $key_3069 = { 63 06 [2] 47 08 [2] 6c 24 [2] 42 06 [2] 56 1d [2] 59 07 [2] 47 1a [2] 45 1b [2] 5e 1d [2] 42 1a [2] 5e 35 }

  condition:
    any of them
}