rule TTP_XOR_QUAD_CurrentVersionRun_0e76 {
  strings:
    $key_0e76 = { 5d 19 [2] 79 17 [2] 52 3b [2] 7c 19 [2] 68 02 [2] 67 18 [2] 79 05 [2] 7b 04 [2] 60 02 [2] 7c 05 [2] 60 2a }

  condition:
    any of them
}