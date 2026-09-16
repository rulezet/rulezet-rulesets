rule TTP_XOR_QUAD_CurrentVersionRun_6a1a {
  strings:
    $key_6a1a = { 39 75 [2] 1d 7b [2] 36 57 [2] 18 75 [2] 0c 6e [2] 03 74 [2] 1d 69 [2] 1f 68 [2] 04 6e [2] 18 69 [2] 04 46 }

  condition:
    any of them
}