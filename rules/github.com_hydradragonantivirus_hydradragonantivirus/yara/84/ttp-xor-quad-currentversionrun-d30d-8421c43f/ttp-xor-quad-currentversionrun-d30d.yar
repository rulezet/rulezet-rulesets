rule TTP_XOR_QUAD_CurrentVersionRun_d30d {
  strings:
    $key_d30d = { 80 62 [2] a4 6c [2] 8f 40 [2] a1 62 [2] b5 79 [2] ba 63 [2] a4 7e [2] a6 7f [2] bd 79 [2] a1 7e [2] bd 51 }

  condition:
    any of them
}