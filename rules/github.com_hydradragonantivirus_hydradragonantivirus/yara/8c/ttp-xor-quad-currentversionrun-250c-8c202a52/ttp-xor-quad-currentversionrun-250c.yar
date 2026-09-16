rule TTP_XOR_QUAD_CurrentVersionRun_250c {
  strings:
    $key_250c = { 76 63 [2] 52 6d [2] 79 41 [2] 57 63 [2] 43 78 [2] 4c 62 [2] 52 7f [2] 50 7e [2] 4b 78 [2] 57 7f [2] 4b 50 }

  condition:
    any of them
}