rule TTP_XOR_QUAD_CurrentVersionRun_0741 {
  strings:
    $key_0741 = { 54 2e [2] 70 20 [2] 5b 0c [2] 75 2e [2] 61 35 [2] 6e 2f [2] 70 32 [2] 72 33 [2] 69 35 [2] 75 32 [2] 69 1d }

  condition:
    any of them
}