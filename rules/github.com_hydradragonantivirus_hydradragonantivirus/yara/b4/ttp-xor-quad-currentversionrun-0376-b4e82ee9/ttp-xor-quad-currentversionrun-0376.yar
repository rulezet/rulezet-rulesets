rule TTP_XOR_QUAD_CurrentVersionRun_0376 {
  strings:
    $key_0376 = { 50 19 [2] 74 17 [2] 5f 3b [2] 71 19 [2] 65 02 [2] 6a 18 [2] 74 05 [2] 76 04 [2] 6d 02 [2] 71 05 [2] 6d 2a }

  condition:
    any of them
}