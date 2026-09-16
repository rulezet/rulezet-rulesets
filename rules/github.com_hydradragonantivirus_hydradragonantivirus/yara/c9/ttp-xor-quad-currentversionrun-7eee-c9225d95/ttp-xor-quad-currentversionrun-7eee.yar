rule TTP_XOR_QUAD_CurrentVersionRun_7eee {
  strings:
    $key_7eee = { 2d 81 [2] 09 8f [2] 22 a3 [2] 0c 81 [2] 18 9a [2] 17 80 [2] 09 9d [2] 0b 9c [2] 10 9a [2] 0c 9d [2] 10 b2 }

  condition:
    any of them
}