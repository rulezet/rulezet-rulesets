rule TTP_XOR_QUAD_CurrentVersionRun_6cda {
  strings:
    $key_6cda = { 3f b5 [2] 1b bb [2] 30 97 [2] 1e b5 [2] 0a ae [2] 05 b4 [2] 1b a9 [2] 19 a8 [2] 02 ae [2] 1e a9 [2] 02 86 }

  condition:
    any of them
}