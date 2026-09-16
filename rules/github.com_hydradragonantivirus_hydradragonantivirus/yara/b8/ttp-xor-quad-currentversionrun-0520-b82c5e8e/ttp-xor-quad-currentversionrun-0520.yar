rule TTP_XOR_QUAD_CurrentVersionRun_0520 {
  strings:
    $key_0520 = { 56 4f [2] 72 41 [2] 59 6d [2] 77 4f [2] 63 54 [2] 6c 4e [2] 72 53 [2] 70 52 [2] 6b 54 [2] 77 53 [2] 6b 7c }

  condition:
    any of them
}