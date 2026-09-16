rule TTP_XOR_QUAD_CurrentVersionRun_3060 {
  strings:
    $key_3060 = { 63 0f [2] 47 01 [2] 6c 2d [2] 42 0f [2] 56 14 [2] 59 0e [2] 47 13 [2] 45 12 [2] 5e 14 [2] 42 13 [2] 5e 3c }

  condition:
    any of them
}