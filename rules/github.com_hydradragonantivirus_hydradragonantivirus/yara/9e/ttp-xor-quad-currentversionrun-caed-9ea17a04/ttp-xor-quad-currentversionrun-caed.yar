rule TTP_XOR_QUAD_CurrentVersionRun_caed {
  strings:
    $key_caed = { 99 82 [2] bd 8c [2] 96 a0 [2] b8 82 [2] ac 99 [2] a3 83 [2] bd 9e [2] bf 9f [2] a4 99 [2] b8 9e [2] a4 b1 }

  condition:
    any of them
}