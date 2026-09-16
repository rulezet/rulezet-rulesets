rule TTP_XOR_QUAD_CurrentVersionRun_dbeb {
  strings:
    $key_dbeb = { 88 84 [2] ac 8a [2] 87 a6 [2] a9 84 [2] bd 9f [2] b2 85 [2] ac 98 [2] ae 99 [2] b5 9f [2] a9 98 [2] b5 b7 }

  condition:
    any of them
}