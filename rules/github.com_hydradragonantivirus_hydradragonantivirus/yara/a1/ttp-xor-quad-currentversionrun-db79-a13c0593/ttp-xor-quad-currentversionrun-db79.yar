rule TTP_XOR_QUAD_CurrentVersionRun_db79 {
  strings:
    $key_db79 = { 88 16 [2] ac 18 [2] 87 34 [2] a9 16 [2] bd 0d [2] b2 17 [2] ac 0a [2] ae 0b [2] b5 0d [2] a9 0a [2] b5 25 }

  condition:
    any of them
}