rule TTP_XOR_QUAD_CurrentVersionRun_526c {
  strings:
    $key_526c = { 01 03 [2] 25 0d [2] 0e 21 [2] 20 03 [2] 34 18 [2] 3b 02 [2] 25 1f [2] 27 1e [2] 3c 18 [2] 20 1f [2] 3c 30 }

  condition:
    any of them
}