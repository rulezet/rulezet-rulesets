rule TTP_XOR_QUAD_CurrentVersionRun_6a7d {
  strings:
    $key_6a7d = { 39 12 [2] 1d 1c [2] 36 30 [2] 18 12 [2] 0c 09 [2] 03 13 [2] 1d 0e [2] 1f 0f [2] 04 09 [2] 18 0e [2] 04 21 }

  condition:
    any of them
}