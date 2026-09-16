rule TTP_XOR_QUAD_CurrentVersionRun_4b76 {
  strings:
    $key_4b76 = { 18 19 [2] 3c 17 [2] 17 3b [2] 39 19 [2] 2d 02 [2] 22 18 [2] 3c 05 [2] 3e 04 [2] 25 02 [2] 39 05 [2] 25 2a }

  condition:
    any of them
}