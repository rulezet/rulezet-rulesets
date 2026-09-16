rule TTP_XOR_QUAD_CurrentVersionRun_6c7d {
  strings:
    $key_6c7d = { 3f 12 [2] 1b 1c [2] 30 30 [2] 1e 12 [2] 0a 09 [2] 05 13 [2] 1b 0e [2] 19 0f [2] 02 09 [2] 1e 0e [2] 02 21 }

  condition:
    any of them
}