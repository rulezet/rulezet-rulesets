rule TTP_XOR_QUAD_CurrentVersionRun_c828 {
  strings:
    $key_c828 = { 9b 47 [2] bf 49 [2] 94 65 [2] ba 47 [2] ae 5c [2] a1 46 [2] bf 5b [2] bd 5a [2] a6 5c [2] ba 5b [2] a6 74 }

  condition:
    any of them
}