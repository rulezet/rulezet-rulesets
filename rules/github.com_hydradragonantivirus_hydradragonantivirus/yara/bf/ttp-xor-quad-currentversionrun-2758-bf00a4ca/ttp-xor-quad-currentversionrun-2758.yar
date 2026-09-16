rule TTP_XOR_QUAD_CurrentVersionRun_2758 {
  strings:
    $key_2758 = { 74 37 [2] 50 39 [2] 7b 15 [2] 55 37 [2] 41 2c [2] 4e 36 [2] 50 2b [2] 52 2a [2] 49 2c [2] 55 2b [2] 49 04 }

  condition:
    any of them
}