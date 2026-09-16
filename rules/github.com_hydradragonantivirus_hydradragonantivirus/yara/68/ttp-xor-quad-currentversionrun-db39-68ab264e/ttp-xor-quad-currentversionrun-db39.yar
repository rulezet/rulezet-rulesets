rule TTP_XOR_QUAD_CurrentVersionRun_db39 {
  strings:
    $key_db39 = { 88 56 [2] ac 58 [2] 87 74 [2] a9 56 [2] bd 4d [2] b2 57 [2] ac 4a [2] ae 4b [2] b5 4d [2] a9 4a [2] b5 65 }

  condition:
    any of them
}