rule TTP_XOR_QUAD_CurrentVersionRun_db0c {
  strings:
    $key_db0c = { 88 63 [2] ac 6d [2] 87 41 [2] a9 63 [2] bd 78 [2] b2 62 [2] ac 7f [2] ae 7e [2] b5 78 [2] a9 7f [2] b5 50 }

  condition:
    any of them
}