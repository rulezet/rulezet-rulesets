rule TTP_XOR_QUAD_CurrentVersionRun_a766 {
  strings:
    $key_a766 = { f4 09 [2] d0 07 [2] fb 2b [2] d5 09 [2] c1 12 [2] ce 08 [2] d0 15 [2] d2 14 [2] c9 12 [2] d5 15 [2] c9 3a }

  condition:
    any of them
}