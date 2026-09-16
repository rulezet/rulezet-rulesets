rule TTP_XOR_QUAD_CurrentVersionRun_f669 {
  strings:
    $key_f669 = { a5 06 [2] 81 08 [2] aa 24 [2] 84 06 [2] 90 1d [2] 9f 07 [2] 81 1a [2] 83 1b [2] 98 1d [2] 84 1a [2] 98 35 }

  condition:
    any of them
}