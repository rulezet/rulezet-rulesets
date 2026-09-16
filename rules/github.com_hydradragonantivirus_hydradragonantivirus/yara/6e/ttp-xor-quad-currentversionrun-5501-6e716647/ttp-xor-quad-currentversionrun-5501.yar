rule TTP_XOR_QUAD_CurrentVersionRun_5501 {
  strings:
    $key_5501 = { 06 6e [2] 22 60 [2] 09 4c [2] 27 6e [2] 33 75 [2] 3c 6f [2] 22 72 [2] 20 73 [2] 3b 75 [2] 27 72 [2] 3b 5d }

  condition:
    any of them
}