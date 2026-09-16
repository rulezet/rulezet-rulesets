rule TTP_XOR_QUAD_CurrentVersionRun_caf9 {
  strings:
    $key_caf9 = { 99 96 [2] bd 98 [2] 96 b4 [2] b8 96 [2] ac 8d [2] a3 97 [2] bd 8a [2] bf 8b [2] a4 8d [2] b8 8a [2] a4 a5 }

  condition:
    any of them
}