rule TTP_XOR_QUAD_CurrentVersionRun_db25 {
  strings:
    $key_db25 = { 88 4a [2] ac 44 [2] 87 68 [2] a9 4a [2] bd 51 [2] b2 4b [2] ac 56 [2] ae 57 [2] b5 51 [2] a9 56 [2] b5 79 }

  condition:
    any of them
}