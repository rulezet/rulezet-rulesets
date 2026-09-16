rule TTP_XOR_QUAD_CurrentVersionRun_3e6d {
  strings:
    $key_3e6d = { 6d 02 [2] 49 0c [2] 62 20 [2] 4c 02 [2] 58 19 [2] 57 03 [2] 49 1e [2] 4b 1f [2] 50 19 [2] 4c 1e [2] 50 31 }

  condition:
    any of them
}