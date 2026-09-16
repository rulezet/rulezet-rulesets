rule TTP_XOR_QUAD_CurrentVersionRun_3f2b {
  strings:
    $key_3f2b = { 6c 44 [2] 48 4a [2] 63 66 [2] 4d 44 [2] 59 5f [2] 56 45 [2] 48 58 [2] 4a 59 [2] 51 5f [2] 4d 58 [2] 51 77 }

  condition:
    any of them
}