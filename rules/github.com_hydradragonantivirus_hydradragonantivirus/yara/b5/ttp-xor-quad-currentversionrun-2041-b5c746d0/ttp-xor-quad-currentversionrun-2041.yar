rule TTP_XOR_QUAD_CurrentVersionRun_2041 {
  strings:
    $key_2041 = { 73 2e [2] 57 20 [2] 7c 0c [2] 52 2e [2] 46 35 [2] 49 2f [2] 57 32 [2] 55 33 [2] 4e 35 [2] 52 32 [2] 4e 1d }

  condition:
    any of them
}