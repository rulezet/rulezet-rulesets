rule TTP_XOR_QUAD_CurrentVersionRun_db23 {
  strings:
    $key_db23 = { 88 4c [2] ac 42 [2] 87 6e [2] a9 4c [2] bd 57 [2] b2 4d [2] ac 50 [2] ae 51 [2] b5 57 [2] a9 50 [2] b5 7f }

  condition:
    any of them
}