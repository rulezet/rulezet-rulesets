rule TTP_XOR_QUAD_CurrentVersionRun_2036 {
  strings:
    $key_2036 = { 73 59 [2] 57 57 [2] 7c 7b [2] 52 59 [2] 46 42 [2] 49 58 [2] 57 45 [2] 55 44 [2] 4e 42 [2] 52 45 [2] 4e 6a }

  condition:
    any of them
}