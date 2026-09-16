rule TTP_XOR_QUAD_CurrentVersionRun_526a {
  strings:
    $key_526a = { 01 05 [2] 25 0b [2] 0e 27 [2] 20 05 [2] 34 1e [2] 3b 04 [2] 25 19 [2] 27 18 [2] 3c 1e [2] 20 19 [2] 3c 36 }

  condition:
    any of them
}