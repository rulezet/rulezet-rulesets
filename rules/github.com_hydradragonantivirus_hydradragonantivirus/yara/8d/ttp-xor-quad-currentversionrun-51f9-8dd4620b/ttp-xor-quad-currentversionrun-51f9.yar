rule TTP_XOR_QUAD_CurrentVersionRun_51f9 {
  strings:
    $key_51f9 = { 02 96 [2] 26 98 [2] 0d b4 [2] 23 96 [2] 37 8d [2] 38 97 [2] 26 8a [2] 24 8b [2] 3f 8d [2] 23 8a [2] 3f a5 }

  condition:
    any of them
}