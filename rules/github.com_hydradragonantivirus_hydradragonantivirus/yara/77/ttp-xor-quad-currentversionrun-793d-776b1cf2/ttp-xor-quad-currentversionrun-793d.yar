rule TTP_XOR_QUAD_CurrentVersionRun_793d {
  strings:
    $key_793d = { 2a 52 [2] 0e 5c [2] 25 70 [2] 0b 52 [2] 1f 49 [2] 10 53 [2] 0e 4e [2] 0c 4f [2] 17 49 [2] 0b 4e [2] 17 61 }

  condition:
    any of them
}