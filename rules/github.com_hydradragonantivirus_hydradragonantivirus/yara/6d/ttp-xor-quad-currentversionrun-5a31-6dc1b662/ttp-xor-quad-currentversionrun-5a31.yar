rule TTP_XOR_QUAD_CurrentVersionRun_5a31 {
  strings:
    $key_5a31 = { 09 5e [2] 2d 50 [2] 06 7c [2] 28 5e [2] 3c 45 [2] 33 5f [2] 2d 42 [2] 2f 43 [2] 34 45 [2] 28 42 [2] 34 6d }

  condition:
    any of them
}