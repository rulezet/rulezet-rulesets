rule TTP_XOR_QUAD_CurrentVersionRun_1640 {
  strings:
    $key_1640 = { 45 2f [2] 61 21 [2] 4a 0d [2] 64 2f [2] 70 34 [2] 7f 2e [2] 61 33 [2] 63 32 [2] 78 34 [2] 64 33 [2] 78 1c }

  condition:
    any of them
}