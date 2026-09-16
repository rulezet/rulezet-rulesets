rule TTP_XOR_QUAD_CurrentVersionRun_3271 {
  strings:
    $key_3271 = { 61 1e [2] 45 10 [2] 6e 3c [2] 40 1e [2] 54 05 [2] 5b 1f [2] 45 02 [2] 47 03 [2] 5c 05 [2] 40 02 [2] 5c 2d }

  condition:
    any of them
}