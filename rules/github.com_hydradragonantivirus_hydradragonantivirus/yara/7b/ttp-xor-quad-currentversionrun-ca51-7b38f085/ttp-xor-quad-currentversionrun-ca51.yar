rule TTP_XOR_QUAD_CurrentVersionRun_ca51 {
  strings:
    $key_ca51 = { 99 3e [2] bd 30 [2] 96 1c [2] b8 3e [2] ac 25 [2] a3 3f [2] bd 22 [2] bf 23 [2] a4 25 [2] b8 22 [2] a4 0d }

  condition:
    any of them
}