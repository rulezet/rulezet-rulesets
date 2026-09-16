rule TTP_XOR_QUAD_CurrentVersionRun_3e6c {
  strings:
    $key_3e6c = { 6d 03 [2] 49 0d [2] 62 21 [2] 4c 03 [2] 58 18 [2] 57 02 [2] 49 1f [2] 4b 1e [2] 50 18 [2] 4c 1f [2] 50 30 }

  condition:
    any of them
}