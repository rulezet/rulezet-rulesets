rule TTP_XOR_QUAD_CurrentVersionRun_3750 {
  strings:
    $key_3750 = { 64 3f [2] 40 31 [2] 6b 1d [2] 45 3f [2] 51 24 [2] 5e 3e [2] 40 23 [2] 42 22 [2] 59 24 [2] 45 23 [2] 59 0c }

  condition:
    any of them
}