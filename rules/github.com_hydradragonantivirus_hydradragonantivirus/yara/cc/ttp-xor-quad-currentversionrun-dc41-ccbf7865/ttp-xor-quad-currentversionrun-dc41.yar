rule TTP_XOR_QUAD_CurrentVersionRun_dc41 {
  strings:
    $key_dc41 = { 8f 2e [2] ab 20 [2] 80 0c [2] ae 2e [2] ba 35 [2] b5 2f [2] ab 32 [2] a9 33 [2] b2 35 [2] ae 32 [2] b2 1d }

  condition:
    any of them
}