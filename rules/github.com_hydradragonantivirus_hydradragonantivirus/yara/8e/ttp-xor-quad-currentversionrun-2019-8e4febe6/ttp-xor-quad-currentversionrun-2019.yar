rule TTP_XOR_QUAD_CurrentVersionRun_2019 {
  strings:
    $key_2019 = { 73 76 [2] 57 78 [2] 7c 54 [2] 52 76 [2] 46 6d [2] 49 77 [2] 57 6a [2] 55 6b [2] 4e 6d [2] 52 6a [2] 4e 45 }

  condition:
    any of them
}