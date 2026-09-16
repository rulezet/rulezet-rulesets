rule TTP_XOR_QUAD_CurrentVersionRun_2059 {
  strings:
    $key_2059 = { 73 36 [2] 57 38 [2] 7c 14 [2] 52 36 [2] 46 2d [2] 49 37 [2] 57 2a [2] 55 2b [2] 4e 2d [2] 52 2a [2] 4e 05 }

  condition:
    any of them
}