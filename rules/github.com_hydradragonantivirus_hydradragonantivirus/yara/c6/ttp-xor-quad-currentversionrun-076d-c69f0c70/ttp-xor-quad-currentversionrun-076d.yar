rule TTP_XOR_QUAD_CurrentVersionRun_076d {
  strings:
    $key_076d = { 54 02 [2] 70 0c [2] 5b 20 [2] 75 02 [2] 61 19 [2] 6e 03 [2] 70 1e [2] 72 1f [2] 69 19 [2] 75 1e [2] 69 31 }

  condition:
    any of them
}