rule TTP_XOR_QUAD_CurrentVersionRun_1a76 {
  strings:
    $key_1a76 = { 49 19 [2] 6d 17 [2] 46 3b [2] 68 19 [2] 7c 02 [2] 73 18 [2] 6d 05 [2] 6f 04 [2] 74 02 [2] 68 05 [2] 74 2a }

  condition:
    any of them
}