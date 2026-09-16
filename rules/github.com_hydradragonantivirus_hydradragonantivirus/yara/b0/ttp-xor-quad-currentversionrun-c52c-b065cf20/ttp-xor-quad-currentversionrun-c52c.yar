rule TTP_XOR_QUAD_CurrentVersionRun_c52c {
  strings:
    $key_c52c = { 96 43 [2] b2 4d [2] 99 61 [2] b7 43 [2] a3 58 [2] ac 42 [2] b2 5f [2] b0 5e [2] ab 58 [2] b7 5f [2] ab 70 }

  condition:
    any of them
}