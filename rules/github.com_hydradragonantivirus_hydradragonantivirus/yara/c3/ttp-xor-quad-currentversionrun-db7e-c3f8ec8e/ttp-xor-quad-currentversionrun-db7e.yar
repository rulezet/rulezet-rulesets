rule TTP_XOR_QUAD_CurrentVersionRun_db7e {
  strings:
    $key_db7e = { 88 11 [2] ac 1f [2] 87 33 [2] a9 11 [2] bd 0a [2] b2 10 [2] ac 0d [2] ae 0c [2] b5 0a [2] a9 0d [2] b5 22 }

  condition:
    any of them
}