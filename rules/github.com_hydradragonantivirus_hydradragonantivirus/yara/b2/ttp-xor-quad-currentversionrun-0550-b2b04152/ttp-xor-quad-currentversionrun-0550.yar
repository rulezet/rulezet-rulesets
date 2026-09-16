rule TTP_XOR_QUAD_CurrentVersionRun_0550 {
  strings:
    $key_0550 = { 56 3f [2] 72 31 [2] 59 1d [2] 77 3f [2] 63 24 [2] 6c 3e [2] 72 23 [2] 70 22 [2] 6b 24 [2] 77 23 [2] 6b 0c }

  condition:
    any of them
}