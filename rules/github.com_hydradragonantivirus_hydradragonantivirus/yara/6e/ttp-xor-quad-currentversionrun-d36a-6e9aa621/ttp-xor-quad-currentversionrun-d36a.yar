rule TTP_XOR_QUAD_CurrentVersionRun_d36a {
  strings:
    $key_d36a = { 80 05 [2] a4 0b [2] 8f 27 [2] a1 05 [2] b5 1e [2] ba 04 [2] a4 19 [2] a6 18 [2] bd 1e [2] a1 19 [2] bd 36 }

  condition:
    any of them
}