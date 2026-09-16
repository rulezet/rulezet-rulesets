rule TTP_XOR_QUAD_CurrentVersionRun_d400 {
  strings:
    $key_d400 = { 87 6f [2] a3 61 [2] 88 4d [2] a6 6f [2] b2 74 [2] bd 6e [2] a3 73 [2] a1 72 [2] ba 74 [2] a6 73 [2] ba 5c }

  condition:
    any of them
}