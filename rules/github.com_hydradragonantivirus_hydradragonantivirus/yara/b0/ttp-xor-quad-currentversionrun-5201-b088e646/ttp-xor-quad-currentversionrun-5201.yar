rule TTP_XOR_QUAD_CurrentVersionRun_5201 {
  strings:
    $key_5201 = { 01 6e [2] 25 60 [2] 0e 4c [2] 20 6e [2] 34 75 [2] 3b 6f [2] 25 72 [2] 27 73 [2] 3c 75 [2] 20 72 [2] 3c 5d }

  condition:
    any of them
}