rule TTP_XOR_QUAD_CurrentVersionRun_2276 {
  strings:
    $key_2276 = { 71 19 [2] 55 17 [2] 7e 3b [2] 50 19 [2] 44 02 [2] 4b 18 [2] 55 05 [2] 57 04 [2] 4c 02 [2] 50 05 [2] 4c 2a }

  condition:
    any of them
}