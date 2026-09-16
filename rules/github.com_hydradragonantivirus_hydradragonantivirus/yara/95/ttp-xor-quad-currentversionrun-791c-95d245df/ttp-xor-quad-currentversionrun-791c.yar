rule TTP_XOR_QUAD_CurrentVersionRun_791c {
  strings:
    $key_791c = { 2a 73 [2] 0e 7d [2] 25 51 [2] 0b 73 [2] 1f 68 [2] 10 72 [2] 0e 6f [2] 0c 6e [2] 17 68 [2] 0b 6f [2] 17 40 }

  condition:
    any of them
}