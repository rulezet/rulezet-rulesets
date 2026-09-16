rule TTP_XOR_QUAD_CurrentVersionRun_db16 {
  strings:
    $key_db16 = { 88 79 [2] ac 77 [2] 87 5b [2] a9 79 [2] bd 62 [2] b2 78 [2] ac 65 [2] ae 64 [2] b5 62 [2] a9 65 [2] b5 4a }

  condition:
    any of them
}