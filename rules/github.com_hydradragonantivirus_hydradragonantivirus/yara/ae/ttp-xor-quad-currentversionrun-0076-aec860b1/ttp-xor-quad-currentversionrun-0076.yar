rule TTP_XOR_QUAD_CurrentVersionRun_0076 {
  strings:
    $key_0076 = { 53 19 [2] 77 17 [2] 5c 3b [2] 72 19 [2] 66 02 [2] 69 18 [2] 77 05 [2] 75 04 [2] 6e 02 [2] 72 05 [2] 6e 2a }

  condition:
    any of them
}