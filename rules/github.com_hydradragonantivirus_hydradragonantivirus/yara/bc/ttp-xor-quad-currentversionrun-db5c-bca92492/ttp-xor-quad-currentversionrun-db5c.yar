rule TTP_XOR_QUAD_CurrentVersionRun_db5c {
  strings:
    $key_db5c = { 88 33 [2] ac 3d [2] 87 11 [2] a9 33 [2] bd 28 [2] b2 32 [2] ac 2f [2] ae 2e [2] b5 28 [2] a9 2f [2] b5 00 }

  condition:
    any of them
}