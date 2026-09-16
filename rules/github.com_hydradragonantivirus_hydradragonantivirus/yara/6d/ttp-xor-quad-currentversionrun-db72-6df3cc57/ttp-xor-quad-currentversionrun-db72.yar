rule TTP_XOR_QUAD_CurrentVersionRun_db72 {
  strings:
    $key_db72 = { 88 1d [2] ac 13 [2] 87 3f [2] a9 1d [2] bd 06 [2] b2 1c [2] ac 01 [2] ae 00 [2] b5 06 [2] a9 01 [2] b5 2e }

  condition:
    any of them
}