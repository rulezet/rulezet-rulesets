rule TTP_XOR_QUAD_CurrentVersionRun_4e1c {
  strings:
    $key_4e1c = { 1d 73 [2] 39 7d [2] 12 51 [2] 3c 73 [2] 28 68 [2] 27 72 [2] 39 6f [2] 3b 6e [2] 20 68 [2] 3c 6f [2] 20 40 }

  condition:
    any of them
}