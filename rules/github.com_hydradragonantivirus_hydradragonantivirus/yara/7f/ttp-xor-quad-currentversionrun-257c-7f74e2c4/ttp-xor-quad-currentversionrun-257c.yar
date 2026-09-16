rule TTP_XOR_QUAD_CurrentVersionRun_257c {
  strings:
    $key_257c = { 76 13 [2] 52 1d [2] 79 31 [2] 57 13 [2] 43 08 [2] 4c 12 [2] 52 0f [2] 50 0e [2] 4b 08 [2] 57 0f [2] 4b 20 }

  condition:
    any of them
}