rule TTP_XOR_QUAD_CurrentVersionRun_3730 {
  strings:
    $key_3730 = { 64 5f [2] 40 51 [2] 6b 7d [2] 45 5f [2] 51 44 [2] 5e 5e [2] 40 43 [2] 42 42 [2] 59 44 [2] 45 43 [2] 59 6c }

  condition:
    any of them
}