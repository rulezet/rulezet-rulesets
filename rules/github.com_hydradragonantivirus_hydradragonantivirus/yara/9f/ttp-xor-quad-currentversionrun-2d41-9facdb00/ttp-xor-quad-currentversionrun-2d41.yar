rule TTP_XOR_QUAD_CurrentVersionRun_2d41 {
  strings:
    $key_2d41 = { 7e 2e [2] 5a 20 [2] 71 0c [2] 5f 2e [2] 4b 35 [2] 44 2f [2] 5a 32 [2] 58 33 [2] 43 35 [2] 5f 32 [2] 43 1d }

  condition:
    any of them
}