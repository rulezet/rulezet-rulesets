rule TTP_XOR_QUAD_CurrentVersionRun_db54 {
  strings:
    $key_db54 = { 88 3b [2] ac 35 [2] 87 19 [2] a9 3b [2] bd 20 [2] b2 3a [2] ac 27 [2] ae 26 [2] b5 20 [2] a9 27 [2] b5 08 }

  condition:
    any of them
}