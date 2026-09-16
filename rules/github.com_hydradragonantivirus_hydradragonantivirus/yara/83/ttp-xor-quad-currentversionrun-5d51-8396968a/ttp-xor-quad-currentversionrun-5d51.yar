rule TTP_XOR_QUAD_CurrentVersionRun_5d51 {
  strings:
    $key_5d51 = { 0e 3e [2] 2a 30 [2] 01 1c [2] 2f 3e [2] 3b 25 [2] 34 3f [2] 2a 22 [2] 28 23 [2] 33 25 [2] 2f 22 [2] 33 0d }

  condition:
    any of them
}