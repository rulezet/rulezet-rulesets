rule TTP_XOR_QUAD_CurrentVersionRun_d301 {
  strings:
    $key_d301 = { 80 6e [2] a4 60 [2] 8f 4c [2] a1 6e [2] b5 75 [2] ba 6f [2] a4 72 [2] a6 73 [2] bd 75 [2] a1 72 [2] bd 5d }

  condition:
    any of them
}