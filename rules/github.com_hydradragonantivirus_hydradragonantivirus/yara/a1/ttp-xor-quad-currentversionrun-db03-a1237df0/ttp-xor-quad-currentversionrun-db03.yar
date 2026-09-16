rule TTP_XOR_QUAD_CurrentVersionRun_db03 {
  strings:
    $key_db03 = { 88 6c [2] ac 62 [2] 87 4e [2] a9 6c [2] bd 77 [2] b2 6d [2] ac 70 [2] ae 71 [2] b5 77 [2] a9 70 [2] b5 5f }

  condition:
    any of them
}