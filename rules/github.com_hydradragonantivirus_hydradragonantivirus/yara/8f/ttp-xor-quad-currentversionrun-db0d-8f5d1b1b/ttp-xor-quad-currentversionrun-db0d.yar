rule TTP_XOR_QUAD_CurrentVersionRun_db0d {
  strings:
    $key_db0d = { 88 62 [2] ac 6c [2] 87 40 [2] a9 62 [2] bd 79 [2] b2 63 [2] ac 7e [2] ae 7f [2] b5 79 [2] a9 7e [2] b5 51 }

  condition:
    any of them
}