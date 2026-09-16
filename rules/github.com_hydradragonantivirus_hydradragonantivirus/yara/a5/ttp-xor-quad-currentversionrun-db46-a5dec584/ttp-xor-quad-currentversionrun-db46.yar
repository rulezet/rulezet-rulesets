rule TTP_XOR_QUAD_CurrentVersionRun_db46 {
  strings:
    $key_db46 = { 88 29 [2] ac 27 [2] 87 0b [2] a9 29 [2] bd 32 [2] b2 28 [2] ac 35 [2] ae 34 [2] b5 32 [2] a9 35 [2] b5 1a }

  condition:
    any of them
}