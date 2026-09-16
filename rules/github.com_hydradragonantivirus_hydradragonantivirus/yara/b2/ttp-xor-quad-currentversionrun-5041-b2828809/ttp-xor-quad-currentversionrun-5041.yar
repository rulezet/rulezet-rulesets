rule TTP_XOR_QUAD_CurrentVersionRun_5041 {
  strings:
    $key_5041 = { 03 2e [2] 27 20 [2] 0c 0c [2] 22 2e [2] 36 35 [2] 39 2f [2] 27 32 [2] 25 33 [2] 3e 35 [2] 22 32 [2] 3e 1d }

  condition:
    any of them
}