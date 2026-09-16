rule TTP_XOR_QUAD_CurrentVersionRun_db6c {
  strings:
    $key_db6c = { 88 03 [2] ac 0d [2] 87 21 [2] a9 03 [2] bd 18 [2] b2 02 [2] ac 1f [2] ae 1e [2] b5 18 [2] a9 1f [2] b5 30 }

  condition:
    any of them
}