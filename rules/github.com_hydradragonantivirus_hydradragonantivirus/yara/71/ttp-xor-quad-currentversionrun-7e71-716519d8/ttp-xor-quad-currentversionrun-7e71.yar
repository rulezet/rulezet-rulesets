rule TTP_XOR_QUAD_CurrentVersionRun_7e71 {
  strings:
    $key_7e71 = { 2d 1e [2] 09 10 [2] 22 3c [2] 0c 1e [2] 18 05 [2] 17 1f [2] 09 02 [2] 0b 03 [2] 10 05 [2] 0c 02 [2] 10 2d }

  condition:
    any of them
}