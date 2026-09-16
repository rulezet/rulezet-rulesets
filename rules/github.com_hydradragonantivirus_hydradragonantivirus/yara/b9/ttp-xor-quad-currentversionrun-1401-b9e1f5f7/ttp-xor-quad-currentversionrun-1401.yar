rule TTP_XOR_QUAD_CurrentVersionRun_1401 {
  strings:
    $key_1401 = { 47 6e [2] 63 60 [2] 48 4c [2] 66 6e [2] 72 75 [2] 7d 6f [2] 63 72 [2] 61 73 [2] 7a 75 [2] 66 72 [2] 7a 5d }

  condition:
    any of them
}