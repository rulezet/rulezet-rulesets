rule TTP_XOR_QUAD_CurrentVersionRun_6c7c {
  strings:
    $key_6c7c = { 3f 13 [2] 1b 1d [2] 30 31 [2] 1e 13 [2] 0a 08 [2] 05 12 [2] 1b 0f [2] 19 0e [2] 02 08 [2] 1e 0f [2] 02 20 }

  condition:
    any of them
}