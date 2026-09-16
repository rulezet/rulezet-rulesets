rule TTP_XOR_QUAD_CurrentVersionRun_2341 {
  strings:
    $key_2341 = { 70 2e [2] 54 20 [2] 7f 0c [2] 51 2e [2] 45 35 [2] 4a 2f [2] 54 32 [2] 56 33 [2] 4d 35 [2] 51 32 [2] 4d 1d }

  condition:
    any of them
}