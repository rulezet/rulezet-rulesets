rule TTP_XOR_QUAD_CurrentVersionRun_731c {
  strings:
    $key_731c = { 20 73 [2] 04 7d [2] 2f 51 [2] 01 73 [2] 15 68 [2] 1a 72 [2] 04 6f [2] 06 6e [2] 1d 68 [2] 01 6f [2] 1d 40 }

  condition:
    any of them
}