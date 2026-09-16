rule TTP_XOR_QUAD_CurrentVersionRun_1e11 {
  strings:
    $key_1e11 = { 4d 7e [2] 69 70 [2] 42 5c [2] 6c 7e [2] 78 65 [2] 77 7f [2] 69 62 [2] 6b 63 [2] 70 65 [2] 6c 62 [2] 70 4d }

  condition:
    any of them
}