rule TTP_XOR_QUAD_CurrentVersionRun_db37 {
  strings:
    $key_db37 = { 88 58 [2] ac 56 [2] 87 7a [2] a9 58 [2] bd 43 [2] b2 59 [2] ac 44 [2] ae 45 [2] b5 43 [2] a9 44 [2] b5 6b }

  condition:
    any of them
}