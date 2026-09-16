rule TTP_XOR_QUAD_CurrentVersionRun_ef69 {
  strings:
    $key_ef69 = { bc 06 [2] 98 08 [2] b3 24 [2] 9d 06 [2] 89 1d [2] 86 07 [2] 98 1a [2] 9a 1b [2] 81 1d [2] 9d 1a [2] 81 35 }

  condition:
    any of them
}