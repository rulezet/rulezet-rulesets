rule TTP_XOR_QUAD_CurrentVersionRun_db60 {
  strings:
    $key_db60 = { 88 0f [2] ac 01 [2] 87 2d [2] a9 0f [2] bd 14 [2] b2 0e [2] ac 13 [2] ae 12 [2] b5 14 [2] a9 13 [2] b5 3c }

  condition:
    any of them
}