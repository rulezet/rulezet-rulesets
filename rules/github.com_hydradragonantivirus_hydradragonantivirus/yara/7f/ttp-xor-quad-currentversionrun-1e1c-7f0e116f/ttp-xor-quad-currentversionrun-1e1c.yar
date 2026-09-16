rule TTP_XOR_QUAD_CurrentVersionRun_1e1c {
  strings:
    $key_1e1c = { 4d 73 [2] 69 7d [2] 42 51 [2] 6c 73 [2] 78 68 [2] 77 72 [2] 69 6f [2] 6b 6e [2] 70 68 [2] 6c 6f [2] 70 40 }

  condition:
    any of them
}