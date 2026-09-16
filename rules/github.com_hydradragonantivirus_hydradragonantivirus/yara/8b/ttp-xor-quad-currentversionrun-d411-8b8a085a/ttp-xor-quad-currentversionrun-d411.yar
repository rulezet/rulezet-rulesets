rule TTP_XOR_QUAD_CurrentVersionRun_d411 {
  strings:
    $key_d411 = { 87 7e [2] a3 70 [2] 88 5c [2] a6 7e [2] b2 65 [2] bd 7f [2] a3 62 [2] a1 63 [2] ba 65 [2] a6 62 [2] ba 4d }

  condition:
    any of them
}