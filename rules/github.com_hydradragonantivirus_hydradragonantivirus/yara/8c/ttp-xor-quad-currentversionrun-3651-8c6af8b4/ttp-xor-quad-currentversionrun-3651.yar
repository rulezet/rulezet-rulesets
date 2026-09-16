rule TTP_XOR_QUAD_CurrentVersionRun_3651 {
  strings:
    $key_3651 = { 65 3e [2] 41 30 [2] 6a 1c [2] 44 3e [2] 50 25 [2] 5f 3f [2] 41 22 [2] 43 23 [2] 58 25 [2] 44 22 [2] 58 0d }

  condition:
    any of them
}