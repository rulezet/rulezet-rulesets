rule TTP_XOR_QUAD_CurrentVersionRun_0701 {
  strings:
    $key_0701 = { 54 6e [2] 70 60 [2] 5b 4c [2] 75 6e [2] 61 75 [2] 6e 6f [2] 70 72 [2] 72 73 [2] 69 75 [2] 75 72 [2] 69 5d }

  condition:
    any of them
}