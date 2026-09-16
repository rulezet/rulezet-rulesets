rule TTP_XOR_QUAD_CurrentVersionRun_e941 {
  strings:
    $key_e941 = { ba 2e [2] 9e 20 [2] b5 0c [2] 9b 2e [2] 8f 35 [2] 80 2f [2] 9e 32 [2] 9c 33 [2] 87 35 [2] 9b 32 [2] 87 1d }

  condition:
    any of them
}