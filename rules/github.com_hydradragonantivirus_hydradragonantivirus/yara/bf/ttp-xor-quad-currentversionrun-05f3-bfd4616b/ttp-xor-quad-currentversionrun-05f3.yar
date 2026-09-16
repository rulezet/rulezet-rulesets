rule TTP_XOR_QUAD_CurrentVersionRun_05f3 {
  strings:
    $key_05f3 = { 56 9c [2] 72 92 [2] 59 be [2] 77 9c [2] 63 87 [2] 6c 9d [2] 72 80 [2] 70 81 [2] 6b 87 [2] 77 80 [2] 6b af }

  condition:
    any of them
}