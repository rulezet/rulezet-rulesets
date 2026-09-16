rule TTP_XOR_QUAD_CurrentVersionRun_0750 {
  strings:
    $key_0750 = { 54 3f [2] 70 31 [2] 5b 1d [2] 75 3f [2] 61 24 [2] 6e 3e [2] 70 23 [2] 72 22 [2] 69 24 [2] 75 23 [2] 69 0c }

  condition:
    any of them
}