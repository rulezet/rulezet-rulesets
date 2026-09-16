rule TTP_XOR_QUAD_CurrentVersionRun_5d21 {
  strings:
    $key_5d21 = { 0e 4e [2] 2a 40 [2] 01 6c [2] 2f 4e [2] 3b 55 [2] 34 4f [2] 2a 52 [2] 28 53 [2] 33 55 [2] 2f 52 [2] 33 7d }

  condition:
    any of them
}