rule TTP_XOR_QUAD_CurrentVersionRun_6f1c {
  strings:
    $key_6f1c = { 3c 73 [2] 18 7d [2] 33 51 [2] 1d 73 [2] 09 68 [2] 06 72 [2] 18 6f [2] 1a 6e [2] 01 68 [2] 1d 6f [2] 01 40 }

  condition:
    any of them
}