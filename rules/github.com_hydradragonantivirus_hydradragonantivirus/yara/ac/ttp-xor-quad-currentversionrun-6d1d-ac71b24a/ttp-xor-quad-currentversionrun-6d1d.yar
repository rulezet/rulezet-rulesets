rule TTP_XOR_QUAD_CurrentVersionRun_6d1d {
  strings:
    $key_6d1d = { 3e 72 [2] 1a 7c [2] 31 50 [2] 1f 72 [2] 0b 69 [2] 04 73 [2] 1a 6e [2] 18 6f [2] 03 69 [2] 1f 6e [2] 03 41 }

  condition:
    any of them
}