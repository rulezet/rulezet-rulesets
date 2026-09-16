rule TTP_XOR_QUAD_CurrentVersionRun_db4e {
  strings:
    $key_db4e = { 88 21 [2] ac 2f [2] 87 03 [2] a9 21 [2] bd 3a [2] b2 20 [2] ac 3d [2] ae 3c [2] b5 3a [2] a9 3d [2] b5 12 }

  condition:
    any of them
}