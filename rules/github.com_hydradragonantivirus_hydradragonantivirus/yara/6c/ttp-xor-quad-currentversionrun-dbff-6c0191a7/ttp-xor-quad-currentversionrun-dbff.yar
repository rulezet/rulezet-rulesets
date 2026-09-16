rule TTP_XOR_QUAD_CurrentVersionRun_dbff {
  strings:
    $key_dbff = { 88 90 [2] ac 9e [2] 87 b2 [2] a9 90 [2] bd 8b [2] b2 91 [2] ac 8c [2] ae 8d [2] b5 8b [2] a9 8c [2] b5 a3 }

  condition:
    any of them
}