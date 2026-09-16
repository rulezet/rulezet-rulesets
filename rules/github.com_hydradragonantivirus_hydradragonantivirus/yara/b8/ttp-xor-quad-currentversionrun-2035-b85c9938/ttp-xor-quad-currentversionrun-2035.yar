rule TTP_XOR_QUAD_CurrentVersionRun_2035 {
  strings:
    $key_2035 = { 73 5a [2] 57 54 [2] 7c 78 [2] 52 5a [2] 46 41 [2] 49 5b [2] 57 46 [2] 55 47 [2] 4e 41 [2] 52 46 [2] 4e 69 }

  condition:
    any of them
}