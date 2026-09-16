rule TTP_XOR_QUAD_CurrentVersionRun_d30c {
  strings:
    $key_d30c = { 80 63 [2] a4 6d [2] 8f 41 [2] a1 63 [2] b5 78 [2] ba 62 [2] a4 7f [2] a6 7e [2] bd 78 [2] a1 7f [2] bd 50 }

  condition:
    any of them
}