rule TTP_XOR_QUAD_CurrentVersionRun_516d {
  strings:
    $key_516d = { 02 02 [2] 26 0c [2] 0d 20 [2] 23 02 [2] 37 19 [2] 38 03 [2] 26 1e [2] 24 1f [2] 3f 19 [2] 23 1e [2] 3f 31 }

  condition:
    any of them
}