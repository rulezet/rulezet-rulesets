rule TTP_XOR_QUAD_CurrentVersionRun_c5ed {
  strings:
    $key_c5ed = { 96 82 [2] b2 8c [2] 99 a0 [2] b7 82 [2] a3 99 [2] ac 83 [2] b2 9e [2] b0 9f [2] ab 99 [2] b7 9e [2] ab b1 }

  condition:
    any of them
}