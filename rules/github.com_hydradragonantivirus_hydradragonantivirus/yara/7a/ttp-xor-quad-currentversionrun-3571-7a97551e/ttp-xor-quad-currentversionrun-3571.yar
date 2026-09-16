rule TTP_XOR_QUAD_CurrentVersionRun_3571 {
  strings:
    $key_3571 = { 66 1e [2] 42 10 [2] 69 3c [2] 47 1e [2] 53 05 [2] 5c 1f [2] 42 02 [2] 40 03 [2] 5b 05 [2] 47 02 [2] 5b 2d }

  condition:
    any of them
}