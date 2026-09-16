rule TTP_XOR_QUAD_CurrentVersionRun_ca00 {
  strings:
    $key_ca00 = { 99 6f [2] bd 61 [2] 96 4d [2] b8 6f [2] ac 74 [2] a3 6e [2] bd 73 [2] bf 72 [2] a4 74 [2] b8 73 [2] a4 5c }

  condition:
    any of them
}