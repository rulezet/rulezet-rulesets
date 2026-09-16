rule TTP_XOR_QUAD_CurrentVersionRun_106c {
  strings:
    $key_106c = { 43 03 [2] 67 0d [2] 4c 21 [2] 62 03 [2] 76 18 [2] 79 02 [2] 67 1f [2] 65 1e [2] 7e 18 [2] 62 1f [2] 7e 30 }

  condition:
    any of them
}