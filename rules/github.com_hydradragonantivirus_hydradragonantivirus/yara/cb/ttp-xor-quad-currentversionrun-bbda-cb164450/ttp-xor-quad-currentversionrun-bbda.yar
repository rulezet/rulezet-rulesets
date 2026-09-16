rule TTP_XOR_QUAD_CurrentVersionRun_bbda {
  strings:
    $key_bbda = { e8 b5 [2] cc bb [2] e7 97 [2] c9 b5 [2] dd ae [2] d2 b4 [2] cc a9 [2] ce a8 [2] d5 ae [2] c9 a9 [2] d5 86 }

  condition:
    any of them
}