rule TTP_XOR_QUAD_CurrentVersionRun_3a7d {
  strings:
    $key_3a7d = { 69 12 [2] 4d 1c [2] 66 30 [2] 48 12 [2] 5c 09 [2] 53 13 [2] 4d 0e [2] 4f 0f [2] 54 09 [2] 48 0e [2] 54 21 }

  condition:
    any of them
}