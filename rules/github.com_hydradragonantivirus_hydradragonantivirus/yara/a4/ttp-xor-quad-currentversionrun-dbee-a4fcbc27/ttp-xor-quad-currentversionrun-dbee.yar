rule TTP_XOR_QUAD_CurrentVersionRun_dbee {
  strings:
    $key_dbee = { 88 81 [2] ac 8f [2] 87 a3 [2] a9 81 [2] bd 9a [2] b2 80 [2] ac 9d [2] ae 9c [2] b5 9a [2] a9 9d [2] b5 b2 }

  condition:
    any of them
}