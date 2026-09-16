rule TTP_XOR_QUAD_CurrentVersionRun_db35 {
  strings:
    $key_db35 = { 88 5a [2] ac 54 [2] 87 78 [2] a9 5a [2] bd 41 [2] b2 5b [2] ac 46 [2] ae 47 [2] b5 41 [2] a9 46 [2] b5 69 }

  condition:
    any of them
}