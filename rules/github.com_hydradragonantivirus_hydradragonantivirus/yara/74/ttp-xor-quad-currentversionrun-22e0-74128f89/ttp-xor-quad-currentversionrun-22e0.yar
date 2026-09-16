rule TTP_XOR_QUAD_CurrentVersionRun_22e0 {
  strings:
    $key_22e0 = { 71 8f [2] 55 81 [2] 7e ad [2] 50 8f [2] 44 94 [2] 4b 8e [2] 55 93 [2] 57 92 [2] 4c 94 [2] 50 93 [2] 4c bc }

  condition:
    any of them
}