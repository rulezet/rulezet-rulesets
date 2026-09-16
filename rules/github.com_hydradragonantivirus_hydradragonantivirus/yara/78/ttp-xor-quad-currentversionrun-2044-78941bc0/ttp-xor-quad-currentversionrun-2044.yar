rule TTP_XOR_QUAD_CurrentVersionRun_2044 {
  strings:
    $key_2044 = { 73 2b [2] 57 25 [2] 7c 09 [2] 52 2b [2] 46 30 [2] 49 2a [2] 57 37 [2] 55 36 [2] 4e 30 [2] 52 37 [2] 4e 18 }

  condition:
    any of them
}