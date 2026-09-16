rule TTP_XOR_QUAD_CurrentVersionRun_187c {
  strings:
    $key_187c = { 4b 13 [2] 6f 1d [2] 44 31 [2] 6a 13 [2] 7e 08 [2] 71 12 [2] 6f 0f [2] 6d 0e [2] 76 08 [2] 6a 0f [2] 76 20 }

  condition:
    any of them
}