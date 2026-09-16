rule TTP_XOR_QUAD_CurrentVersionRun_2029 {
  strings:
    $key_2029 = { 73 46 [2] 57 48 [2] 7c 64 [2] 52 46 [2] 46 5d [2] 49 47 [2] 57 5a [2] 55 5b [2] 4e 5d [2] 52 5a [2] 4e 75 }

  condition:
    any of them
}