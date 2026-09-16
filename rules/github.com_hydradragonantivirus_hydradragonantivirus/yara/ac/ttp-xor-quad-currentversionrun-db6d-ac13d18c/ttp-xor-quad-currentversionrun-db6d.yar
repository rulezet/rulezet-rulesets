rule TTP_XOR_QUAD_CurrentVersionRun_db6d {
  strings:
    $key_db6d = { 88 02 [2] ac 0c [2] 87 20 [2] a9 02 [2] bd 19 [2] b2 03 [2] ac 1e [2] ae 1f [2] b5 19 [2] a9 1e [2] b5 31 }

  condition:
    any of them
}