rule TTP_XOR_QUAD_CurrentVersionRun_5000 {
  strings:
    $key_5000 = { 03 6f [2] 27 61 [2] 0c 4d [2] 22 6f [2] 36 74 [2] 39 6e [2] 27 73 [2] 25 72 [2] 3e 74 [2] 22 73 [2] 3e 5c }

  condition:
    any of them
}