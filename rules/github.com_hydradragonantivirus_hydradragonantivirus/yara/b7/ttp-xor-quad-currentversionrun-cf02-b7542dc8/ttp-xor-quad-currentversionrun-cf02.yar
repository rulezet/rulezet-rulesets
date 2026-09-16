rule TTP_XOR_QUAD_CurrentVersionRun_cf02 {
  strings:
    $key_cf02 = { 9c 6d [2] b8 63 [2] 93 4f [2] bd 6d [2] a9 76 [2] a6 6c [2] b8 71 [2] ba 70 [2] a1 76 [2] bd 71 [2] a1 5e }

  condition:
    any of them
}