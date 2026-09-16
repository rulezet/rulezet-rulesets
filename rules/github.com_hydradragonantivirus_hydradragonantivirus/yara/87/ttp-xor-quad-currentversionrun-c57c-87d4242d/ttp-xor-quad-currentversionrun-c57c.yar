rule TTP_XOR_QUAD_CurrentVersionRun_c57c {
  strings:
    $key_c57c = { 96 13 [2] b2 1d [2] 99 31 [2] b7 13 [2] a3 08 [2] ac 12 [2] b2 0f [2] b0 0e [2] ab 08 [2] b7 0f [2] ab 20 }

  condition:
    any of them
}