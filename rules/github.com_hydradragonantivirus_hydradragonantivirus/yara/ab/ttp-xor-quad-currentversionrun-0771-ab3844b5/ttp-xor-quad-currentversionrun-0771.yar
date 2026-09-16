rule TTP_XOR_QUAD_CurrentVersionRun_0771 {
  strings:
    $key_0771 = { 54 1e [2] 70 10 [2] 5b 3c [2] 75 1e [2] 61 05 [2] 6e 1f [2] 70 02 [2] 72 03 [2] 69 05 [2] 75 02 [2] 69 2d }

  condition:
    any of them
}