rule TTP_XOR_QUAD_CurrentVersionRun_e720 {
  strings:
    $key_e720 = { b4 4f [2] 90 41 [2] bb 6d [2] 95 4f [2] 81 54 [2] 8e 4e [2] 90 53 [2] 92 52 [2] 89 54 [2] 95 53 [2] 89 7c }

  condition:
    any of them
}