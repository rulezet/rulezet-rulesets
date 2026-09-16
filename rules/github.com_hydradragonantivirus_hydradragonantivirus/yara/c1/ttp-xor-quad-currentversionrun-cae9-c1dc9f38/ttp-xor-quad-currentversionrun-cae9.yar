rule TTP_XOR_QUAD_CurrentVersionRun_cae9 {
  strings:
    $key_cae9 = { 99 86 [2] bd 88 [2] 96 a4 [2] b8 86 [2] ac 9d [2] a3 87 [2] bd 9a [2] bf 9b [2] a4 9d [2] b8 9a [2] a4 b5 }

  condition:
    any of them
}