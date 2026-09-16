rule TTP_XOR_QUAD_CurrentVersionRun_1cee {
  strings:
    $key_1cee = { 4f 81 [2] 6b 8f [2] 40 a3 [2] 6e 81 [2] 7a 9a [2] 75 80 [2] 6b 9d [2] 69 9c [2] 72 9a [2] 6e 9d [2] 72 b2 }

  condition:
    any of them
}