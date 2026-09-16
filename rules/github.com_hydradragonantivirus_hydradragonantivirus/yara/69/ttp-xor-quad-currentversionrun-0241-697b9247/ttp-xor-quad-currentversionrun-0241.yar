rule TTP_XOR_QUAD_CurrentVersionRun_0241 {
  strings:
    $key_0241 = { 51 2e [2] 75 20 [2] 5e 0c [2] 70 2e [2] 64 35 [2] 6b 2f [2] 75 32 [2] 77 33 [2] 6c 35 [2] 70 32 [2] 6c 1d }

  condition:
    any of them
}