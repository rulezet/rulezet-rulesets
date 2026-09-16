rule TTP_XOR_QUAD_CurrentVersionRun_6a6d {
  strings:
    $key_6a6d = { 39 02 [2] 1d 0c [2] 36 20 [2] 18 02 [2] 0c 19 [2] 03 03 [2] 1d 1e [2] 1f 1f [2] 04 19 [2] 18 1e [2] 04 31 }

  condition:
    any of them
}