rule TTP_XOR_QUAD_CurrentVersionRun_d402 {
  strings:
    $key_d402 = { 87 6d [2] a3 63 [2] 88 4f [2] a6 6d [2] b2 76 [2] bd 6c [2] a3 71 [2] a1 70 [2] ba 76 [2] a6 71 [2] ba 5e }

  condition:
    any of them
}