rule TTP_XOR_QUAD_CurrentVersionRun_db67 {
  strings:
    $key_db67 = { 88 08 [2] ac 06 [2] 87 2a [2] a9 08 [2] bd 13 [2] b2 09 [2] ac 14 [2] ae 15 [2] b5 13 [2] a9 14 [2] b5 3b }

  condition:
    any of them
}