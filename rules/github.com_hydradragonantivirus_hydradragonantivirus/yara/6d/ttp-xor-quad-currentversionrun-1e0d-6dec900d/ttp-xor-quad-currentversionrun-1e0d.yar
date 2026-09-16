rule TTP_XOR_QUAD_CurrentVersionRun_1e0d {
  strings:
    $key_1e0d = { 4d 62 [2] 69 6c [2] 42 40 [2] 6c 62 [2] 78 79 [2] 77 63 [2] 69 7e [2] 6b 7f [2] 70 79 [2] 6c 7e [2] 70 51 }

  condition:
    any of them
}