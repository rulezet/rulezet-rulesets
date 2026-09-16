rule TTP_XOR_QUAD_CurrentVersionRun_4b6d {
  strings:
    $key_4b6d = { 18 02 [2] 3c 0c [2] 17 20 [2] 39 02 [2] 2d 19 [2] 22 03 [2] 3c 1e [2] 3e 1f [2] 25 19 [2] 39 1e [2] 25 31 }

  condition:
    any of them
}