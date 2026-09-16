rule TTP_XOR_QUAD_CurrentVersionRun_c56c {
  strings:
    $key_c56c = { 96 03 [2] b2 0d [2] 99 21 [2] b7 03 [2] a3 18 [2] ac 02 [2] b2 1f [2] b0 1e [2] ab 18 [2] b7 1f [2] ab 30 }

  condition:
    any of them
}