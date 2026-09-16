rule TTP_XOR_QUAD_CurrentVersionRun_c5fd {
  strings:
    $key_c5fd = { 96 92 [2] b2 9c [2] 99 b0 [2] b7 92 [2] a3 89 [2] ac 93 [2] b2 8e [2] b0 8f [2] ab 89 [2] b7 8e [2] ab a1 }

  condition:
    any of them
}