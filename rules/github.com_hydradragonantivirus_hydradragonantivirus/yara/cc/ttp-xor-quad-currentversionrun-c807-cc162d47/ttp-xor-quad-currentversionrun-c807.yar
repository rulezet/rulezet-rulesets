rule TTP_XOR_QUAD_CurrentVersionRun_c807 {
  strings:
    $key_c807 = { 9b 68 [2] bf 66 [2] 94 4a [2] ba 68 [2] ae 73 [2] a1 69 [2] bf 74 [2] bd 75 [2] a6 73 [2] ba 74 [2] a6 5b }

  condition:
    any of them
}