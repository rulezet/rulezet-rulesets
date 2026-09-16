rule TTP_XOR_QUAD_CurrentVersionRun_6a5d {
  strings:
    $key_6a5d = { 39 32 [2] 1d 3c [2] 36 10 [2] 18 32 [2] 0c 29 [2] 03 33 [2] 1d 2e [2] 1f 2f [2] 04 29 [2] 18 2e [2] 04 01 }

  condition:
    any of them
}