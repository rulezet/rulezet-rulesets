rule TTP_XOR_QUAD_CurrentVersionRun_c866 {
  strings:
    $key_c866 = { 9b 09 [2] bf 07 [2] 94 2b [2] ba 09 [2] ae 12 [2] a1 08 [2] bf 15 [2] bd 14 [2] a6 12 [2] ba 15 [2] a6 3a }

  condition:
    any of them
}