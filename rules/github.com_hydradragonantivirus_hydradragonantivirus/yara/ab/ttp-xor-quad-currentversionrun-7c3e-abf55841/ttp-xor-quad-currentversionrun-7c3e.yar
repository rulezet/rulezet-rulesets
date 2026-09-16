rule TTP_XOR_QUAD_CurrentVersionRun_7c3e {
  strings:
    $key_7c3e = { 2f 51 [2] 0b 5f [2] 20 73 [2] 0e 51 [2] 1a 4a [2] 15 50 [2] 0b 4d [2] 09 4c [2] 12 4a [2] 0e 4d [2] 12 62 }

  condition:
    any of them
}