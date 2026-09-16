rule TTP_XOR_QUAD_CurrentVersionRun_db1d {
  strings:
    $key_db1d = { 88 72 [2] ac 7c [2] 87 50 [2] a9 72 [2] bd 69 [2] b2 73 [2] ac 6e [2] ae 6f [2] b5 69 [2] a9 6e [2] b5 41 }

  condition:
    any of them
}