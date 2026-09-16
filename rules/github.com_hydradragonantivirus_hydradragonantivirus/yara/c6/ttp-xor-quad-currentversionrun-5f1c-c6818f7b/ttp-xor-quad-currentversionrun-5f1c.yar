rule TTP_XOR_QUAD_CurrentVersionRun_5f1c {
  strings:
    $key_5f1c = { 0c 73 [2] 28 7d [2] 03 51 [2] 2d 73 [2] 39 68 [2] 36 72 [2] 28 6f [2] 2a 6e [2] 31 68 [2] 2d 6f [2] 31 40 }

  condition:
    any of them
}