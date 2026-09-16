rule TTP_XOR_QUAD_CurrentVersionRun_19f3 {
  strings:
    $key_19f3 = { 4a 9c [2] 6e 92 [2] 45 be [2] 6b 9c [2] 7f 87 [2] 70 9d [2] 6e 80 [2] 6c 81 [2] 77 87 [2] 6b 80 [2] 77 af }

  condition:
    any of them
}