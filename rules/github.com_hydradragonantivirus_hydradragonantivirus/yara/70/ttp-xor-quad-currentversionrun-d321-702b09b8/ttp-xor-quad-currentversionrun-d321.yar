rule TTP_XOR_QUAD_CurrentVersionRun_d321 {
  strings:
    $key_d321 = { 80 4e [2] a4 40 [2] 8f 6c [2] a1 4e [2] b5 55 [2] ba 4f [2] a4 52 [2] a6 53 [2] bd 55 [2] a1 52 [2] bd 7d }

  condition:
    any of them
}