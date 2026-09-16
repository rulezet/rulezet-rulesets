rule TTP_XOR_QUAD_CurrentVersionRun_2735 {
  strings:
    $key_2735 = { 74 5a [2] 50 54 [2] 7b 78 [2] 55 5a [2] 41 41 [2] 4e 5b [2] 50 46 [2] 52 47 [2] 49 41 [2] 55 46 [2] 49 69 }

  condition:
    any of them
}