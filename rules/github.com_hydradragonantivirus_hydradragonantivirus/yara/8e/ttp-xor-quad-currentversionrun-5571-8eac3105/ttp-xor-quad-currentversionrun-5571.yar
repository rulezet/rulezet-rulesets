rule TTP_XOR_QUAD_CurrentVersionRun_5571 {
  strings:
    $key_5571 = { 06 1e [2] 22 10 [2] 09 3c [2] 27 1e [2] 33 05 [2] 3c 1f [2] 22 02 [2] 20 03 [2] 3b 05 [2] 27 02 [2] 3b 2d }

  condition:
    any of them
}