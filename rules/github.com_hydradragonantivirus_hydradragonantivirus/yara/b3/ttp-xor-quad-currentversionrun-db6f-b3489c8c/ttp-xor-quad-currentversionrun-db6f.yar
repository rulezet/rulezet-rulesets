rule TTP_XOR_QUAD_CurrentVersionRun_db6f {
  strings:
    $key_db6f = { 88 00 [2] ac 0e [2] 87 22 [2] a9 00 [2] bd 1b [2] b2 01 [2] ac 1c [2] ae 1d [2] b5 1b [2] a9 1c [2] b5 33 }

  condition:
    any of them
}