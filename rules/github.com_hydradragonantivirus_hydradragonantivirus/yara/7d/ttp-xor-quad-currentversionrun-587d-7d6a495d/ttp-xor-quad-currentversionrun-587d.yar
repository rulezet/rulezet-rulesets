rule TTP_XOR_QUAD_CurrentVersionRun_587d {
  strings:
    $key_587d = { 0b 12 [2] 2f 1c [2] 04 30 [2] 2a 12 [2] 3e 09 [2] 31 13 [2] 2f 0e [2] 2d 0f [2] 36 09 [2] 2a 0e [2] 36 21 }

  condition:
    any of them
}