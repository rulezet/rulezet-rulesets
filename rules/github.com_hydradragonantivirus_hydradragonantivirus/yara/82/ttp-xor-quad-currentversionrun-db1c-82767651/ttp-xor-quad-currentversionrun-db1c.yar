rule TTP_XOR_QUAD_CurrentVersionRun_db1c {
  strings:
    $key_db1c = { 88 73 [2] ac 7d [2] 87 51 [2] a9 73 [2] bd 68 [2] b2 72 [2] ac 6f [2] ae 6e [2] b5 68 [2] a9 6f [2] b5 40 }

  condition:
    any of them
}