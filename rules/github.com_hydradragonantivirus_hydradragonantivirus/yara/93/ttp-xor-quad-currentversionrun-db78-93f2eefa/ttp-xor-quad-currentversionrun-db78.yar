rule TTP_XOR_QUAD_CurrentVersionRun_db78 {
  strings:
    $key_db78 = { 88 17 [2] ac 19 [2] 87 35 [2] a9 17 [2] bd 0c [2] b2 16 [2] ac 0b [2] ae 0a [2] b5 0c [2] a9 0b [2] b5 24 }

  condition:
    any of them
}