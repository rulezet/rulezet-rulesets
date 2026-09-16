rule TTP_XOR_QUAD_CurrentVersionRun_076c {
  strings:
    $key_076c = { 54 03 [2] 70 0d [2] 5b 21 [2] 75 03 [2] 61 18 [2] 6e 02 [2] 70 1f [2] 72 1e [2] 69 18 [2] 75 1f [2] 69 30 }

  condition:
    any of them
}