rule TTP_XOR_QUAD_CurrentVersionRun_db2b {
  strings:
    $key_db2b = { 88 44 [2] ac 4a [2] 87 66 [2] a9 44 [2] bd 5f [2] b2 45 [2] ac 58 [2] ae 59 [2] b5 5f [2] a9 58 [2] b5 77 }

  condition:
    any of them
}