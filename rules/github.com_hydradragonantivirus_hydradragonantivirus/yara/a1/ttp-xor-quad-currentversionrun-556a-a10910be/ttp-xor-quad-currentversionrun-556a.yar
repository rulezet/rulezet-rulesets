rule TTP_XOR_QUAD_CurrentVersionRun_556a {
  strings:
    $key_556a = { 06 05 [2] 22 0b [2] 09 27 [2] 27 05 [2] 33 1e [2] 3c 04 [2] 22 19 [2] 20 18 [2] 3b 1e [2] 27 19 [2] 3b 36 }

  condition:
    any of them
}