rule TTP_XOR_QUAD_CurrentVersionRun_3430 {
  strings:
    $key_3430 = { 67 5f [2] 43 51 [2] 68 7d [2] 46 5f [2] 52 44 [2] 5d 5e [2] 43 43 [2] 41 42 [2] 5a 44 [2] 46 43 [2] 5a 6c }

  condition:
    any of them
}