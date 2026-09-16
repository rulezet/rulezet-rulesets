rule TTP_XOR_QUAD_CurrentVersionRun_fa71 {
  strings:
    $key_fa71 = { a9 1e [2] 8d 10 [2] a6 3c [2] 88 1e [2] 9c 05 [2] 93 1f [2] 8d 02 [2] 8f 03 [2] 94 05 [2] 88 02 [2] 94 2d }

  condition:
    any of them
}