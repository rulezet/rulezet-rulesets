rule TTP_XOR_QUAD_CurrentVersionRun_3162 {
  strings:
    $key_3162 = { 62 0d [2] 46 03 [2] 6d 2f [2] 43 0d [2] 57 16 [2] 58 0c [2] 46 11 [2] 44 10 [2] 5f 16 [2] 43 11 [2] 5f 3e }

  condition:
    any of them
}