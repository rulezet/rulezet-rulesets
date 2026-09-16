rule TTP_XOR_QUAD_CurrentVersionRun_c80f {
  strings:
    $key_c80f = { 9b 60 [2] bf 6e [2] 94 42 [2] ba 60 [2] ae 7b [2] a1 61 [2] bf 7c [2] bd 7d [2] a6 7b [2] ba 7c [2] a6 53 }

  condition:
    any of them
}