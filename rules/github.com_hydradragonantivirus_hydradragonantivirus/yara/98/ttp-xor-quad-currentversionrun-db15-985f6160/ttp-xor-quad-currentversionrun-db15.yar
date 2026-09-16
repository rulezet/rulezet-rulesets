rule TTP_XOR_QUAD_CurrentVersionRun_db15 {
  strings:
    $key_db15 = { 88 7a [2] ac 74 [2] 87 58 [2] a9 7a [2] bd 61 [2] b2 7b [2] ac 66 [2] ae 67 [2] b5 61 [2] a9 66 [2] b5 49 }

  condition:
    any of them
}