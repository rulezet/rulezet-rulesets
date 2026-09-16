rule TTP_XOR_QUAD_CurrentVersionRun_1951 {
  strings:
    $key_1951 = { 4a 3e [2] 6e 30 [2] 45 1c [2] 6b 3e [2] 7f 25 [2] 70 3f [2] 6e 22 [2] 6c 23 [2] 77 25 [2] 6b 22 [2] 77 0d }

  condition:
    any of them
}