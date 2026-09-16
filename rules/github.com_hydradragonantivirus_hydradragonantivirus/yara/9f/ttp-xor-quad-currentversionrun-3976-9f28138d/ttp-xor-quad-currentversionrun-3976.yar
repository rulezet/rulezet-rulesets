rule TTP_XOR_QUAD_CurrentVersionRun_3976 {
  strings:
    $key_3976 = { 6a 19 [2] 4e 17 [2] 65 3b [2] 4b 19 [2] 5f 02 [2] 50 18 [2] 4e 05 [2] 4c 04 [2] 57 02 [2] 4b 05 [2] 57 2a }

  condition:
    any of them
}