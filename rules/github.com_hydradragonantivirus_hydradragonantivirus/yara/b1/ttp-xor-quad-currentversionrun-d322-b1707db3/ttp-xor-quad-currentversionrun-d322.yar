rule TTP_XOR_QUAD_CurrentVersionRun_d322 {
  strings:
    $key_d322 = { 80 4d [2] a4 43 [2] 8f 6f [2] a1 4d [2] b5 56 [2] ba 4c [2] a4 51 [2] a6 50 [2] bd 56 [2] a1 51 [2] bd 7e }

  condition:
    any of them
}