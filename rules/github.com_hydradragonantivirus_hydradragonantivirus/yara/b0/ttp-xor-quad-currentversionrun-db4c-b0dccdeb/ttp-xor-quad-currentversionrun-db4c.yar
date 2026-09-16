rule TTP_XOR_QUAD_CurrentVersionRun_db4c {
  strings:
    $key_db4c = { 88 23 [2] ac 2d [2] 87 01 [2] a9 23 [2] bd 38 [2] b2 22 [2] ac 3f [2] ae 3e [2] b5 38 [2] a9 3f [2] b5 10 }

  condition:
    any of them
}