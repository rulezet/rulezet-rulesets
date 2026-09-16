rule TTP_XOR_QUAD_CurrentVersionRun_3751 {
  strings:
    $key_3751 = { 64 3e [2] 40 30 [2] 6b 1c [2] 45 3e [2] 51 25 [2] 5e 3f [2] 40 22 [2] 42 23 [2] 59 25 [2] 45 22 [2] 59 0d }

  condition:
    any of them
}