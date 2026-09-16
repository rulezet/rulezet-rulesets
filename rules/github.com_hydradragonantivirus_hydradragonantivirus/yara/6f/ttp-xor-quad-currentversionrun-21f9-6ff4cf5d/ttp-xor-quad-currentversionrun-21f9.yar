rule TTP_XOR_QUAD_CurrentVersionRun_21f9 {
  strings:
    $key_21f9 = { 72 96 [2] 56 98 [2] 7d b4 [2] 53 96 [2] 47 8d [2] 48 97 [2] 56 8a [2] 54 8b [2] 4f 8d [2] 53 8a [2] 4f a5 }

  condition:
    any of them
}