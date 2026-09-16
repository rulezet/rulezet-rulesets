rule TTP_XOR_QUAD_CurrentVersionRun_4430 {
  strings:
    $key_4430 = { 17 5f [2] 33 51 [2] 18 7d [2] 36 5f [2] 22 44 [2] 2d 5e [2] 33 43 [2] 31 42 [2] 2a 44 [2] 36 43 [2] 2a 6c }

  condition:
    any of them
}