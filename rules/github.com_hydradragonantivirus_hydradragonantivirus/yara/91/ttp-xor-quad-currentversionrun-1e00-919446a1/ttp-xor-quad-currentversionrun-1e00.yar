rule TTP_XOR_QUAD_CurrentVersionRun_1e00 {
  strings:
    $key_1e00 = { 4d 6f [2] 69 61 [2] 42 4d [2] 6c 6f [2] 78 74 [2] 77 6e [2] 69 73 [2] 6b 72 [2] 70 74 [2] 6c 73 [2] 70 5c }

  condition:
    any of them
}