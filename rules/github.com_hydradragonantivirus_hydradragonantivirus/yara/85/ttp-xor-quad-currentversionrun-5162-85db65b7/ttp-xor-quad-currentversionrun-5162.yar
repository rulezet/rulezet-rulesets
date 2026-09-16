rule TTP_XOR_QUAD_CurrentVersionRun_5162 {
  strings:
    $key_5162 = { 02 0d [2] 26 03 [2] 0d 2f [2] 23 0d [2] 37 16 [2] 38 0c [2] 26 11 [2] 24 10 [2] 3f 16 [2] 23 11 [2] 3f 3e }

  condition:
    any of them
}