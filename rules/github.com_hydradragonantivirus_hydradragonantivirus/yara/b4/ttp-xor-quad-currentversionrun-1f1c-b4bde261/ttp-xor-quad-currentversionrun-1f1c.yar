rule TTP_XOR_QUAD_CurrentVersionRun_1f1c {
  strings:
    $key_1f1c = { 4c 73 [2] 68 7d [2] 43 51 [2] 6d 73 [2] 79 68 [2] 76 72 [2] 68 6f [2] 6a 6e [2] 71 68 [2] 6d 6f [2] 71 40 }

  condition:
    any of them
}