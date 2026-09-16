rule TTP_XOR_QUAD_CurrentVersionRun_db47 {
  strings:
    $key_db47 = { 88 28 [2] ac 26 [2] 87 0a [2] a9 28 [2] bd 33 [2] b2 29 [2] ac 34 [2] ae 35 [2] b5 33 [2] a9 34 [2] b5 1b }

  condition:
    any of them
}