rule TTP_XOR_QUAD_CurrentVersionRun_2006 {
  strings:
    $key_2006 = { 73 69 [2] 57 67 [2] 7c 4b [2] 52 69 [2] 46 72 [2] 49 68 [2] 57 75 [2] 55 74 [2] 4e 72 [2] 52 75 [2] 4e 5a }

  condition:
    any of them
}