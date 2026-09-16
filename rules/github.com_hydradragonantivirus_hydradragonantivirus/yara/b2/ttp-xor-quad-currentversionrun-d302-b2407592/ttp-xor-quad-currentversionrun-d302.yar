rule TTP_XOR_QUAD_CurrentVersionRun_d302 {
  strings:
    $key_d302 = { 80 6d [2] a4 63 [2] 8f 4f [2] a1 6d [2] b5 76 [2] ba 6c [2] a4 71 [2] a6 70 [2] bd 76 [2] a1 71 [2] bd 5e }

  condition:
    any of them
}