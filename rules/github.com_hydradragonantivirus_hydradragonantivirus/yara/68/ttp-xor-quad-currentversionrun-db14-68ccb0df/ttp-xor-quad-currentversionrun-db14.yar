rule TTP_XOR_QUAD_CurrentVersionRun_db14 {
  strings:
    $key_db14 = { 88 7b [2] ac 75 [2] 87 59 [2] a9 7b [2] bd 60 [2] b2 7a [2] ac 67 [2] ae 66 [2] b5 60 [2] a9 67 [2] b5 48 }

  condition:
    any of them
}