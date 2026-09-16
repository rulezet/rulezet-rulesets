rule TTP_XOR_QUAD_CurrentVersionRun_78fc {
  strings:
    $key_78fc = { 2b 93 [2] 0f 9d [2] 24 b1 [2] 0a 93 [2] 1e 88 [2] 11 92 [2] 0f 8f [2] 0d 8e [2] 16 88 [2] 0a 8f [2] 16 a0 }

  condition:
    any of them
}