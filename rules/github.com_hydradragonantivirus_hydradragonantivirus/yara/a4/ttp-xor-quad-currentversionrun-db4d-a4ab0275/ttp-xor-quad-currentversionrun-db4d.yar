rule TTP_XOR_QUAD_CurrentVersionRun_db4d {
  strings:
    $key_db4d = { 88 22 [2] ac 2c [2] 87 00 [2] a9 22 [2] bd 39 [2] b2 23 [2] ac 3e [2] ae 3f [2] b5 39 [2] a9 3e [2] b5 11 }

  condition:
    any of them
}