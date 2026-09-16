rule TTP_XOR_QUAD_CurrentVersionRun_db1a {
  strings:
    $key_db1a = { 88 75 [2] ac 7b [2] 87 57 [2] a9 75 [2] bd 6e [2] b2 74 [2] ac 69 [2] ae 68 [2] b5 6e [2] a9 69 [2] b5 46 }

  condition:
    any of them
}