rule TTP_XOR_QUAD_CurrentVersionRun_de2c {
  strings:
    $key_de2c = { 8d 43 [2] a9 4d [2] 82 61 [2] ac 43 [2] b8 58 [2] b7 42 [2] a9 5f [2] ab 5e [2] b0 58 [2] ac 5f [2] b0 70 }

  condition:
    any of them
}