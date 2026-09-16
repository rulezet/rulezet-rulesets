rule TTP_XOR_QUAD_CurrentVersionRun_2016 {
  strings:
    $key_2016 = { 73 79 [2] 57 77 [2] 7c 5b [2] 52 79 [2] 46 62 [2] 49 78 [2] 57 65 [2] 55 64 [2] 4e 62 [2] 52 65 [2] 4e 4a }

  condition:
    any of them
}