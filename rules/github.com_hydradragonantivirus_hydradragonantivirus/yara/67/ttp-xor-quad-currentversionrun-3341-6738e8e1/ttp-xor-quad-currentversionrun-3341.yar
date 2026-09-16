rule TTP_XOR_QUAD_CurrentVersionRun_3341 {
  strings:
    $key_3341 = { 60 2e [2] 44 20 [2] 6f 0c [2] 41 2e [2] 55 35 [2] 5a 2f [2] 44 32 [2] 46 33 [2] 5d 35 [2] 41 32 [2] 5d 1d }

  condition:
    any of them
}