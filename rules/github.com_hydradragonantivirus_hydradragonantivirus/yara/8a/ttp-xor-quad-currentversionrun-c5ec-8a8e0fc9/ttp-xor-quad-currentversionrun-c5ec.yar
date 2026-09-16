rule TTP_XOR_QUAD_CurrentVersionRun_c5ec {
  strings:
    $key_c5ec = { 96 83 [2] b2 8d [2] 99 a1 [2] b7 83 [2] a3 98 [2] ac 82 [2] b2 9f [2] b0 9e [2] ab 98 [2] b7 9f [2] ab b0 }

  condition:
    any of them
}