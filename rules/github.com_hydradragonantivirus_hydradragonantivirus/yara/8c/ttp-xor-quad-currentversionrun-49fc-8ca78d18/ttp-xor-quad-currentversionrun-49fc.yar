rule TTP_XOR_QUAD_CurrentVersionRun_49fc {
  strings:
    $key_49fc = { 1a 93 [2] 3e 9d [2] 15 b1 [2] 3b 93 [2] 2f 88 [2] 20 92 [2] 3e 8f [2] 3c 8e [2] 27 88 [2] 3b 8f [2] 27 a0 }

  condition:
    any of them
}