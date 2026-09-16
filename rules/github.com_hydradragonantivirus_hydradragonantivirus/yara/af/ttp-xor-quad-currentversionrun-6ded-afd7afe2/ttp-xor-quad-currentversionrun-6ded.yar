rule TTP_XOR_QUAD_CurrentVersionRun_6ded {
  strings:
    $key_6ded = { 3e 82 [2] 1a 8c [2] 31 a0 [2] 1f 82 [2] 0b 99 [2] 04 83 [2] 1a 9e [2] 18 9f [2] 03 99 [2] 1f 9e [2] 03 b1 }

  condition:
    any of them
}