rule TTP_XOR_QUAD_CurrentVersionRun_0841 {
  strings:
    $key_0841 = { 5b 2e [2] 7f 20 [2] 54 0c [2] 7a 2e [2] 6e 35 [2] 61 2f [2] 7f 32 [2] 7d 33 [2] 66 35 [2] 7a 32 [2] 66 1d }

  condition:
    any of them
}