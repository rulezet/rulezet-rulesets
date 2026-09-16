rule TTP_XOR_QUAD_CurrentVersionRun_4b41 {
  strings:
    $key_4b41 = { 18 2e [2] 3c 20 [2] 17 0c [2] 39 2e [2] 2d 35 [2] 22 2f [2] 3c 32 [2] 3e 33 [2] 25 35 [2] 39 32 [2] 25 1d }

  condition:
    any of them
}