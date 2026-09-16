rule TTP_XOR_QUAD_CurrentVersionRun_2451 {
  strings:
    $key_2451 = { 77 3e [2] 53 30 [2] 78 1c [2] 56 3e [2] 42 25 [2] 4d 3f [2] 53 22 [2] 51 23 [2] 4a 25 [2] 56 22 [2] 4a 0d }

  condition:
    any of them
}