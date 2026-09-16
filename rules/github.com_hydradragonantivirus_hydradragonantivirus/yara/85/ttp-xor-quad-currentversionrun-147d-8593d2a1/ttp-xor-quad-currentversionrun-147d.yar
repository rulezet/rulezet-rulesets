rule TTP_XOR_QUAD_CurrentVersionRun_147d {
  strings:
    $key_147d = { 47 12 [2] 63 1c [2] 48 30 [2] 66 12 [2] 72 09 [2] 7d 13 [2] 63 0e [2] 61 0f [2] 7a 09 [2] 66 0e [2] 7a 21 }

  condition:
    any of them
}