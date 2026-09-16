rule TTP_XOR_QUAD_CurrentVersionRun_7801 {
  strings:
    $key_7801 = { 2b 6e [2] 0f 60 [2] 24 4c [2] 0a 6e [2] 1e 75 [2] 11 6f [2] 0f 72 [2] 0d 73 [2] 16 75 [2] 0a 72 [2] 16 5d }

  condition:
    any of them
}