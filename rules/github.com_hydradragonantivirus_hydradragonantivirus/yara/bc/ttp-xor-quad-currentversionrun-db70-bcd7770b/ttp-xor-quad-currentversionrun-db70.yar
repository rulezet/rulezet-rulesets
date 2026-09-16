rule TTP_XOR_QUAD_CurrentVersionRun_db70 {
  strings:
    $key_db70 = { 88 1f [2] ac 11 [2] 87 3d [2] a9 1f [2] bd 04 [2] b2 1e [2] ac 03 [2] ae 02 [2] b5 04 [2] a9 03 [2] b5 2c }

  condition:
    any of them
}