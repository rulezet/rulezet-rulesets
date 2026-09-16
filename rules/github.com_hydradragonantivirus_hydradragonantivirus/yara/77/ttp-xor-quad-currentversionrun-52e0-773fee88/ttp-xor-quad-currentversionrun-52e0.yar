rule TTP_XOR_QUAD_CurrentVersionRun_52e0 {
  strings:
    $key_52e0 = { 01 8f [2] 25 81 [2] 0e ad [2] 20 8f [2] 34 94 [2] 3b 8e [2] 25 93 [2] 27 92 [2] 3c 94 [2] 20 93 [2] 3c bc }

  condition:
    any of them
}