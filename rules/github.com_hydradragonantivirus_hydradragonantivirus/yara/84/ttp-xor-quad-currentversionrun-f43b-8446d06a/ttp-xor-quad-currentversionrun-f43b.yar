rule TTP_XOR_QUAD_CurrentVersionRun_f43b {
  strings:
    $key_f43b = { a7 54 [2] 83 5a [2] a8 76 [2] 86 54 [2] 92 4f [2] 9d 55 [2] 83 48 [2] 81 49 [2] 9a 4f [2] 86 48 [2] 9a 67 }

  condition:
    any of them
}