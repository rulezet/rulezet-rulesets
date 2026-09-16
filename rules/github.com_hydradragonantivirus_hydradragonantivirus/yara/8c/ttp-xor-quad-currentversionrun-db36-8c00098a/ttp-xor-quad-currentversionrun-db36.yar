rule TTP_XOR_QUAD_CurrentVersionRun_db36 {
  strings:
    $key_db36 = { 88 59 [2] ac 57 [2] 87 7b [2] a9 59 [2] bd 42 [2] b2 58 [2] ac 45 [2] ae 44 [2] b5 42 [2] a9 45 [2] b5 6a }

  condition:
    any of them
}