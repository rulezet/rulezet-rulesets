rule TTP_XOR_QUAD_CurrentVersionRun_5d33 {
  strings:
    $key_5d33 = { 0e 5c [2] 2a 52 [2] 01 7e [2] 2f 5c [2] 3b 47 [2] 34 5d [2] 2a 40 [2] 28 41 [2] 33 47 [2] 2f 40 [2] 33 6f }

  condition:
    any of them
}