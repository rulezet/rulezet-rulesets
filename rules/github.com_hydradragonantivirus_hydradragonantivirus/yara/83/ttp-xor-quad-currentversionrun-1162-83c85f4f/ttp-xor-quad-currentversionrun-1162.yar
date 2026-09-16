rule TTP_XOR_QUAD_CurrentVersionRun_1162 {
  strings:
    $key_1162 = { 42 0d [2] 66 03 [2] 4d 2f [2] 63 0d [2] 77 16 [2] 78 0c [2] 66 11 [2] 64 10 [2] 7f 16 [2] 63 11 [2] 7f 3e }

  condition:
    any of them
}