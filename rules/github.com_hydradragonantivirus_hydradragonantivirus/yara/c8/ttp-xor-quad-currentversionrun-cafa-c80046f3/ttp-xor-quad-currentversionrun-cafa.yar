rule TTP_XOR_QUAD_CurrentVersionRun_cafa {
  strings:
    $key_cafa = { 99 95 [2] bd 9b [2] 96 b7 [2] b8 95 [2] ac 8e [2] a3 94 [2] bd 89 [2] bf 88 [2] a4 8e [2] b8 89 [2] a4 a6 }

  condition:
    any of them
}