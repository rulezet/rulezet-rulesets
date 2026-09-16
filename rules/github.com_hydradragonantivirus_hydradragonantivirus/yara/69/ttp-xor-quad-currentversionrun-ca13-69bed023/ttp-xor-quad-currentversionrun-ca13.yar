rule TTP_XOR_QUAD_CurrentVersionRun_ca13 {
  strings:
    $key_ca13 = { 99 7c [2] bd 72 [2] 96 5e [2] b8 7c [2] ac 67 [2] a3 7d [2] bd 60 [2] bf 61 [2] a4 67 [2] b8 60 [2] a4 4f }

  condition:
    any of them
}