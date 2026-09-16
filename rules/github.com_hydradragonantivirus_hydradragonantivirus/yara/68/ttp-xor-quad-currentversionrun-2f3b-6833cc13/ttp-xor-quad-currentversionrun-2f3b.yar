rule TTP_XOR_QUAD_CurrentVersionRun_2f3b {
  strings:
    $key_2f3b = { 7c 54 [2] 58 5a [2] 73 76 [2] 5d 54 [2] 49 4f [2] 46 55 [2] 58 48 [2] 5a 49 [2] 41 4f [2] 5d 48 [2] 41 67 }

  condition:
    any of them
}