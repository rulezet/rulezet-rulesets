rule TTP_XOR_QUAD_CurrentVersionRun_631c {
  strings:
    $key_631c = { 30 73 [2] 14 7d [2] 3f 51 [2] 11 73 [2] 05 68 [2] 0a 72 [2] 14 6f [2] 16 6e [2] 0d 68 [2] 11 6f [2] 0d 40 }

  condition:
    any of them
}