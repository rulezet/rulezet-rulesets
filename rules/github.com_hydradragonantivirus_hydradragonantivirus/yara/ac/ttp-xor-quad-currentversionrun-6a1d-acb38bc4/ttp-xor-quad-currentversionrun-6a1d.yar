rule TTP_XOR_QUAD_CurrentVersionRun_6a1d {
  strings:
    $key_6a1d = { 39 72 [2] 1d 7c [2] 36 50 [2] 18 72 [2] 0c 69 [2] 03 73 [2] 1d 6e [2] 1f 6f [2] 04 69 [2] 18 6e [2] 04 41 }

  condition:
    any of them
}