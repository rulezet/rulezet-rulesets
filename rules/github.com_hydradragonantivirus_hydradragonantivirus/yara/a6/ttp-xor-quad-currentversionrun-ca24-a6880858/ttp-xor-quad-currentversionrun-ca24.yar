rule TTP_XOR_QUAD_CurrentVersionRun_ca24 {
  strings:
    $key_ca24 = { 99 4b [2] bd 45 [2] 96 69 [2] b8 4b [2] ac 50 [2] a3 4a [2] bd 57 [2] bf 56 [2] a4 50 [2] b8 57 [2] a4 78 }

  condition:
    any of them
}