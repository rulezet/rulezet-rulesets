rule TTP_XOR_QUAD_CurrentVersionRun_db18 {
  strings:
    $key_db18 = { 88 77 [2] ac 79 [2] 87 55 [2] a9 77 [2] bd 6c [2] b2 76 [2] ac 6b [2] ae 6a [2] b5 6c [2] a9 6b [2] b5 44 }

  condition:
    any of them
}