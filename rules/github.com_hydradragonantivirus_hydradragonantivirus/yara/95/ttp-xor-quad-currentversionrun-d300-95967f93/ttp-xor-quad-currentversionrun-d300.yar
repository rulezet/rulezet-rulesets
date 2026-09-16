rule TTP_XOR_QUAD_CurrentVersionRun_d300 {
  strings:
    $key_d300 = { 80 6f [2] a4 61 [2] 8f 4d [2] a1 6f [2] b5 74 [2] ba 6e [2] a4 73 [2] a6 72 [2] bd 74 [2] a1 73 [2] bd 5c }

  condition:
    any of them
}