rule TTP_XOR_QUAD_CurrentVersionRun_6701 {
  strings:
    $key_6701 = { 34 6e [2] 10 60 [2] 3b 4c [2] 15 6e [2] 01 75 [2] 0e 6f [2] 10 72 [2] 12 73 [2] 09 75 [2] 15 72 [2] 09 5d }

  condition:
    any of them
}