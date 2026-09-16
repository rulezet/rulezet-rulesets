rule TTP_XOR_QUAD_CurrentVersionRun_2476 {
  strings:
    $key_2476 = { 77 19 [2] 53 17 [2] 78 3b [2] 56 19 [2] 42 02 [2] 4d 18 [2] 53 05 [2] 51 04 [2] 4a 02 [2] 56 05 [2] 4a 2a }

  condition:
    any of them
}