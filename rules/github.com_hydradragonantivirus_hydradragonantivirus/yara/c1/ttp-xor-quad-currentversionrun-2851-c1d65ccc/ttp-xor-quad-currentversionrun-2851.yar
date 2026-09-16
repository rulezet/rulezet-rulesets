rule TTP_XOR_QUAD_CurrentVersionRun_2851 {
  strings:
    $key_2851 = { 7b 3e [2] 5f 30 [2] 74 1c [2] 5a 3e [2] 4e 25 [2] 41 3f [2] 5f 22 [2] 5d 23 [2] 46 25 [2] 5a 22 [2] 46 0d }

  condition:
    any of them
}