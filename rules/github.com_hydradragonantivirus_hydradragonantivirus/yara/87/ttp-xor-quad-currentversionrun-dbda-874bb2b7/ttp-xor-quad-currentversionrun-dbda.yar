rule TTP_XOR_QUAD_CurrentVersionRun_dbda {
  strings:
    $key_dbda = { 88 b5 [2] ac bb [2] 87 97 [2] a9 b5 [2] bd ae [2] b2 b4 [2] ac a9 [2] ae a8 [2] b5 ae [2] a9 a9 [2] b5 86 }

  condition:
    any of them
}