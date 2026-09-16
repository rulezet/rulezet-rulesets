rule TTP_XOR_QUAD_CurrentVersionRun_2651 {
  strings:
    $key_2651 = { 75 3e [2] 51 30 [2] 7a 1c [2] 54 3e [2] 40 25 [2] 4f 3f [2] 51 22 [2] 53 23 [2] 48 25 [2] 54 22 [2] 48 0d }

  condition:
    any of them
}