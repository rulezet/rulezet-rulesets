rule TTP_XOR_QUAD_CurrentVersionRun_1f6d {
  strings:
    $key_1f6d = { 4c 02 [2] 68 0c [2] 43 20 [2] 6d 02 [2] 79 19 [2] 76 03 [2] 68 1e [2] 6a 1f [2] 71 19 [2] 6d 1e [2] 71 31 }

  condition:
    any of them
}