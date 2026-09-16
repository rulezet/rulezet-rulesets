rule TTP_XOR_QUAD_CurrentVersionRun_1551 {
  strings:
    $key_1551 = { 46 3e [2] 62 30 [2] 49 1c [2] 67 3e [2] 73 25 [2] 7c 3f [2] 62 22 [2] 60 23 [2] 7b 25 [2] 67 22 [2] 7b 0d }

  condition:
    any of them
}