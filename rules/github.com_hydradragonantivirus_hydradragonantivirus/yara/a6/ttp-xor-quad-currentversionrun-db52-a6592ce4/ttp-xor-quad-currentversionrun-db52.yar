rule TTP_XOR_QUAD_CurrentVersionRun_db52 {
  strings:
    $key_db52 = { 88 3d [2] ac 33 [2] 87 1f [2] a9 3d [2] bd 26 [2] b2 3c [2] ac 21 [2] ae 20 [2] b5 26 [2] a9 21 [2] b5 0e }

  condition:
    any of them
}