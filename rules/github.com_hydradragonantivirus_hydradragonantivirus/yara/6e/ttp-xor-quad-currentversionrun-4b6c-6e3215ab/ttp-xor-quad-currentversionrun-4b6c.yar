rule TTP_XOR_QUAD_CurrentVersionRun_4b6c {
  strings:
    $key_4b6c = { 18 03 [2] 3c 0d [2] 17 21 [2] 39 03 [2] 2d 18 [2] 22 02 [2] 3c 1f [2] 3e 1e [2] 25 18 [2] 39 1f [2] 25 30 }

  condition:
    any of them
}