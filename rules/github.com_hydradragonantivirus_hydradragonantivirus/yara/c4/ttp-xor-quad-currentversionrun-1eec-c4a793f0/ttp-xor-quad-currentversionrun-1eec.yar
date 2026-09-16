rule TTP_XOR_QUAD_CurrentVersionRun_1eec {
  strings:
    $key_1eec = { 4d 83 [2] 69 8d [2] 42 a1 [2] 6c 83 [2] 78 98 [2] 77 82 [2] 69 9f [2] 6b 9e [2] 70 98 [2] 6c 9f [2] 70 b0 }

  condition:
    any of them
}