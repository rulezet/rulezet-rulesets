rule TTP_XOR_QUAD_CurrentVersionRun_522d {
  strings:
    $key_522d = { 01 42 [2] 25 4c [2] 0e 60 [2] 20 42 [2] 34 59 [2] 3b 43 [2] 25 5e [2] 27 5f [2] 3c 59 [2] 20 5e [2] 3c 71 }

  condition:
    any of them
}