rule TTP_XOR_QUAD_CurrentVersionRun_3b76 {
  strings:
    $key_3b76 = { 68 19 [2] 4c 17 [2] 67 3b [2] 49 19 [2] 5d 02 [2] 52 18 [2] 4c 05 [2] 4e 04 [2] 55 02 [2] 49 05 [2] 55 2a }

  condition:
    any of them
}