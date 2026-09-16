rule TTP_XOR_QUAD_CurrentVersionRun_3efc {
  strings:
    $key_3efc = { 6d 93 [2] 49 9d [2] 62 b1 [2] 4c 93 [2] 58 88 [2] 57 92 [2] 49 8f [2] 4b 8e [2] 50 88 [2] 4c 8f [2] 50 a0 }

  condition:
    any of them
}