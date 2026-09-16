rule TTP_XOR_QUAD_CurrentVersionRun_db75 {
  strings:
    $key_db75 = { 88 1a [2] ac 14 [2] 87 38 [2] a9 1a [2] bd 01 [2] b2 1b [2] ac 06 [2] ae 07 [2] b5 01 [2] a9 06 [2] b5 29 }

  condition:
    any of them
}