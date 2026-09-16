rule TTP_XOR_QUAD_CurrentVersionRun_506b {
  strings:
    $key_506b = { 03 04 [2] 27 0a [2] 0c 26 [2] 22 04 [2] 36 1f [2] 39 05 [2] 27 18 [2] 25 19 [2] 3e 1f [2] 22 18 [2] 3e 37 }

  condition:
    any of them
}