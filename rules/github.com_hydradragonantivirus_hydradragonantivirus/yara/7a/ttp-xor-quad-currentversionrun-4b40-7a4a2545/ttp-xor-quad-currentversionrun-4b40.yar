rule TTP_XOR_QUAD_CurrentVersionRun_4b40 {
  strings:
    $key_4b40 = { 18 2f [2] 3c 21 [2] 17 0d [2] 39 2f [2] 2d 34 [2] 22 2e [2] 3c 33 [2] 3e 32 [2] 25 34 [2] 39 33 [2] 25 1c }

  condition:
    any of them
}