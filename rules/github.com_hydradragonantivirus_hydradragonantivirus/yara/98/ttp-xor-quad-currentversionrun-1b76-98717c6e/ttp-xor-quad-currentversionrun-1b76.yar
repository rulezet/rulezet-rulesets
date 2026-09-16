rule TTP_XOR_QUAD_CurrentVersionRun_1b76 {
  strings:
    $key_1b76 = { 48 19 [2] 6c 17 [2] 47 3b [2] 69 19 [2] 7d 02 [2] 72 18 [2] 6c 05 [2] 6e 04 [2] 75 02 [2] 69 05 [2] 75 2a }

  condition:
    any of them
}