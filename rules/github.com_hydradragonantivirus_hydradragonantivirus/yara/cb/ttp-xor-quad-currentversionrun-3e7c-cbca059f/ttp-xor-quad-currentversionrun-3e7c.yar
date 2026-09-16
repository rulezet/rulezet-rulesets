rule TTP_XOR_QUAD_CurrentVersionRun_3e7c {
  strings:
    $key_3e7c = { 6d 13 [2] 49 1d [2] 62 31 [2] 4c 13 [2] 58 08 [2] 57 12 [2] 49 0f [2] 4b 0e [2] 50 08 [2] 4c 0f [2] 50 20 }

  condition:
    any of them
}