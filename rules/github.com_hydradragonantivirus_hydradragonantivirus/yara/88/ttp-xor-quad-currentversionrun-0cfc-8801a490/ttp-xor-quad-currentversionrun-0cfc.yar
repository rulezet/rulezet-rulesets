rule TTP_XOR_QUAD_CurrentVersionRun_0cfc {
  strings:
    $key_0cfc = { 5f 93 [2] 7b 9d [2] 50 b1 [2] 7e 93 [2] 6a 88 [2] 65 92 [2] 7b 8f [2] 79 8e [2] 62 88 [2] 7e 8f [2] 62 a0 }

  condition:
    any of them
}