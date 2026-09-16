rule TTP_XOR_QUAD_CurrentVersionRun_c802 {
  strings:
    $key_c802 = { 9b 6d [2] bf 63 [2] 94 4f [2] ba 6d [2] ae 76 [2] a1 6c [2] bf 71 [2] bd 70 [2] a6 76 [2] ba 71 [2] a6 5e }

  condition:
    any of them
}