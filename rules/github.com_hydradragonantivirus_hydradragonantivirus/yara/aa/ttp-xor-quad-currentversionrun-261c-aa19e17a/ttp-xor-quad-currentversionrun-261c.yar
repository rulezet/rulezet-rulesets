rule TTP_XOR_QUAD_CurrentVersionRun_261c {
  strings:
    $key_261c = { 75 73 [2] 51 7d [2] 7a 51 [2] 54 73 [2] 40 68 [2] 4f 72 [2] 51 6f [2] 53 6e [2] 48 68 [2] 54 6f [2] 48 40 }

  condition:
    any of them
}