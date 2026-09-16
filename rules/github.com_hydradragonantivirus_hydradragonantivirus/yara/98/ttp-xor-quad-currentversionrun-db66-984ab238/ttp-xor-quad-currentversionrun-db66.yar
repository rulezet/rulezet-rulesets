rule TTP_XOR_QUAD_CurrentVersionRun_db66 {
  strings:
    $key_db66 = { 88 09 [2] ac 07 [2] 87 2b [2] a9 09 [2] bd 12 [2] b2 08 [2] ac 15 [2] ae 14 [2] b5 12 [2] a9 15 [2] b5 3a }

  condition:
    any of them
}