rule TTP_XOR_QUAD_CurrentVersionRun_3ded {
  strings:
    $key_3ded = { 6e 82 [2] 4a 8c [2] 61 a0 [2] 4f 82 [2] 5b 99 [2] 54 83 [2] 4a 9e [2] 48 9f [2] 53 99 [2] 4f 9e [2] 53 b1 }

  condition:
    any of them
}