rule TTP_XOR_QUAD_CurrentVersionRun_4476 {
  strings:
    $key_4476 = { 17 19 [2] 33 17 [2] 18 3b [2] 36 19 [2] 22 02 [2] 2d 18 [2] 33 05 [2] 31 04 [2] 2a 02 [2] 36 05 [2] 2a 2a }

  condition:
    any of them
}