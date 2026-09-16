rule TTP_XOR_QUAD_CurrentVersionRun_4651 {
  strings:
    $key_4651 = { 15 3e [2] 31 30 [2] 1a 1c [2] 34 3e [2] 20 25 [2] 2f 3f [2] 31 22 [2] 33 23 [2] 28 25 [2] 34 22 [2] 28 0d }

  condition:
    any of them
}