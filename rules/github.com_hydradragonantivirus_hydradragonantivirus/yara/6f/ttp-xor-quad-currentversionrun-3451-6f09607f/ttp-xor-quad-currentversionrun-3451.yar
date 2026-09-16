rule TTP_XOR_QUAD_CurrentVersionRun_3451 {
  strings:
    $key_3451 = { 67 3e [2] 43 30 [2] 68 1c [2] 46 3e [2] 52 25 [2] 5d 3f [2] 43 22 [2] 41 23 [2] 5a 25 [2] 46 22 [2] 5a 0d }

  condition:
    any of them
}