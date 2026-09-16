rule TTP_XOR_QUAD_CurrentVersionRun_527c {
  strings:
    $key_527c = { 01 13 [2] 25 1d [2] 0e 31 [2] 20 13 [2] 34 08 [2] 3b 12 [2] 25 0f [2] 27 0e [2] 3c 08 [2] 20 0f [2] 3c 20 }

  condition:
    any of them
}