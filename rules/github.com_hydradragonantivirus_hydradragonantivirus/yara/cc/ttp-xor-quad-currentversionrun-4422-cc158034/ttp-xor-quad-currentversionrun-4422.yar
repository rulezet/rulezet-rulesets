rule TTP_XOR_QUAD_CurrentVersionRun_4422 {
  strings:
    $key_4422 = { 17 4d [2] 33 43 [2] 18 6f [2] 36 4d [2] 22 56 [2] 2d 4c [2] 33 51 [2] 31 50 [2] 2a 56 [2] 36 51 [2] 2a 7e }

  condition:
    any of them
}