rule TTP_XOR_QUAD_CurrentVersionRun_3773 {
  strings:
    $key_3773 = { 64 1c [2] 40 12 [2] 6b 3e [2] 45 1c [2] 51 07 [2] 5e 1d [2] 40 00 [2] 42 01 [2] 59 07 [2] 45 00 [2] 59 2f }

  condition:
    any of them
}