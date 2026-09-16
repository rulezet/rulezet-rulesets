rule TTP_XOR_QUAD_CurrentVersionRun_db3e {
  strings:
    $key_db3e = { 88 51 [2] ac 5f [2] 87 73 [2] a9 51 [2] bd 4a [2] b2 50 [2] ac 4d [2] ae 4c [2] b5 4a [2] a9 4d [2] b5 62 }

  condition:
    any of them
}