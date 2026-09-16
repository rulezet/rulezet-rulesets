rule TTP_XOR_QUAD_CurrentVersionRun_7e30 {
  strings:
    $key_7e30 = { 2d 5f [2] 09 51 [2] 22 7d [2] 0c 5f [2] 18 44 [2] 17 5e [2] 09 43 [2] 0b 42 [2] 10 44 [2] 0c 43 [2] 10 6c }

  condition:
    any of them
}