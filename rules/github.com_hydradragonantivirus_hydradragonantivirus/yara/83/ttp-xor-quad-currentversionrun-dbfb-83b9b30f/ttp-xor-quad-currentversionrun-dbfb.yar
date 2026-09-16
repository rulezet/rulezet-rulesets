rule TTP_XOR_QUAD_CurrentVersionRun_dbfb {
  strings:
    $key_dbfb = { 88 94 [2] ac 9a [2] 87 b6 [2] a9 94 [2] bd 8f [2] b2 95 [2] ac 88 [2] ae 89 [2] b5 8f [2] a9 88 [2] b5 a7 }

  condition:
    any of them
}