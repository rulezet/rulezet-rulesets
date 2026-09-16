rule TTP_XOR_QUAD_CurrentVersionRun_dbf8 {
  strings:
    $key_dbf8 = { 88 97 [2] ac 99 [2] 87 b5 [2] a9 97 [2] bd 8c [2] b2 96 [2] ac 8b [2] ae 8a [2] b5 8c [2] a9 8b [2] b5 a4 }

  condition:
    any of them
}