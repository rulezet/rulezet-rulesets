rule TTP_XOR_QUAD_CurrentVersionRun_c541 {
  strings:
    $key_c541 = { 96 2e [2] b2 20 [2] 99 0c [2] b7 2e [2] a3 35 [2] ac 2f [2] b2 32 [2] b0 33 [2] ab 35 [2] b7 32 [2] ab 1d }

  condition:
    any of them
}