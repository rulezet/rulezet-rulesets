rule TTP_XOR_QUAD_CurrentVersionRun_db56 {
  strings:
    $key_db56 = { 88 39 [2] ac 37 [2] 87 1b [2] a9 39 [2] bd 22 [2] b2 38 [2] ac 25 [2] ae 24 [2] b5 22 [2] a9 25 [2] b5 0a }

  condition:
    any of them
}