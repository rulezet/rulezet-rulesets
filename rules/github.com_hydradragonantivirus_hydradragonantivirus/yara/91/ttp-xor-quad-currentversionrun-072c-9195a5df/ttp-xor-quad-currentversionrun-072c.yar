rule TTP_XOR_QUAD_CurrentVersionRun_072c {
  strings:
    $key_072c = { 54 43 [2] 70 4d [2] 5b 61 [2] 75 43 [2] 61 58 [2] 6e 42 [2] 70 5f [2] 72 5e [2] 69 58 [2] 75 5f [2] 69 70 }

  condition:
    any of them
}