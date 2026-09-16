rule TTP_XOR_QUAD_CurrentVersionRun_db1e {
  strings:
    $key_db1e = { 88 71 [2] ac 7f [2] 87 53 [2] a9 71 [2] bd 6a [2] b2 70 [2] ac 6d [2] ae 6c [2] b5 6a [2] a9 6d [2] b5 42 }

  condition:
    any of them
}