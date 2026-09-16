rule TTP_XOR_QUAD_CurrentVersionRun_ca7f {
  strings:
    $key_ca7f = { 99 10 [2] bd 1e [2] 96 32 [2] b8 10 [2] ac 0b [2] a3 11 [2] bd 0c [2] bf 0d [2] a4 0b [2] b8 0c [2] a4 23 }

  condition:
    any of them
}