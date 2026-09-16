rule TTP_XOR_QUAD_CurrentVersionRun_556b {
  strings:
    $key_556b = { 06 04 [2] 22 0a [2] 09 26 [2] 27 04 [2] 33 1f [2] 3c 05 [2] 22 18 [2] 20 19 [2] 3b 1f [2] 27 18 [2] 3b 37 }

  condition:
    any of them
}