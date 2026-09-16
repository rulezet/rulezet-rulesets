rule TTP_XOR_QUAD_CurrentVersionRun_1f6c {
  strings:
    $key_1f6c = { 4c 03 [2] 68 0d [2] 43 21 [2] 6d 03 [2] 79 18 [2] 76 02 [2] 68 1f [2] 6a 1e [2] 71 18 [2] 6d 1f [2] 71 30 }

  condition:
    any of them
}