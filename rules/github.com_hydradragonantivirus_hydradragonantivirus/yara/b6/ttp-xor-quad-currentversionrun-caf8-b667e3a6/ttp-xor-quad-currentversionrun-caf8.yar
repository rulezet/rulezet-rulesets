rule TTP_XOR_QUAD_CurrentVersionRun_caf8 {
  strings:
    $key_caf8 = { 99 97 [2] bd 99 [2] 96 b5 [2] b8 97 [2] ac 8c [2] a3 96 [2] bd 8b [2] bf 8a [2] a4 8c [2] b8 8b [2] a4 a4 }

  condition:
    any of them
}