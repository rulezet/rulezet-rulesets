rule TTP_XOR_QUAD_CurrentVersionRun_1cfc {
  strings:
    $key_1cfc = { 4f 93 [2] 6b 9d [2] 40 b1 [2] 6e 93 [2] 7a 88 [2] 75 92 [2] 6b 8f [2] 69 8e [2] 72 88 [2] 6e 8f [2] 72 a0 }

  condition:
    any of them
}