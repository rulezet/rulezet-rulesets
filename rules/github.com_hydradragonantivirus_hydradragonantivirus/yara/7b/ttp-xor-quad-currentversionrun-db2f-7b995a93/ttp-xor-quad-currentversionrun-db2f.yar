rule TTP_XOR_QUAD_CurrentVersionRun_db2f {
  strings:
    $key_db2f = { 88 40 [2] ac 4e [2] 87 62 [2] a9 40 [2] bd 5b [2] b2 41 [2] ac 5c [2] ae 5d [2] b5 5b [2] a9 5c [2] b5 73 }

  condition:
    any of them
}