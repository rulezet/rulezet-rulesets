rule TTP_XOR_QUAD_CurrentVersionRun_5030 {
  strings:
    $key_5030 = { 03 5f [2] 27 51 [2] 0c 7d [2] 22 5f [2] 36 44 [2] 39 5e [2] 27 43 [2] 25 42 [2] 3e 44 [2] 22 43 [2] 3e 6c }

  condition:
    any of them
}