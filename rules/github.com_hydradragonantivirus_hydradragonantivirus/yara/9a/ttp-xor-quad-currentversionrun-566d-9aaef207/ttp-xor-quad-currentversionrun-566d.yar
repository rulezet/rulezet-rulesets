rule TTP_XOR_QUAD_CurrentVersionRun_566d {
  strings:
    $key_566d = { 05 02 [2] 21 0c [2] 0a 20 [2] 24 02 [2] 30 19 [2] 3f 03 [2] 21 1e [2] 23 1f [2] 38 19 [2] 24 1e [2] 38 31 }

  condition:
    any of them
}