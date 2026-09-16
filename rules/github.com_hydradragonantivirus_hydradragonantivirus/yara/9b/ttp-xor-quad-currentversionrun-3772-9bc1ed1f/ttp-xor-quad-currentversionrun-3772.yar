rule TTP_XOR_QUAD_CurrentVersionRun_3772 {
  strings:
    $key_3772 = { 64 1d [2] 40 13 [2] 6b 3f [2] 45 1d [2] 51 06 [2] 5e 1c [2] 40 01 [2] 42 00 [2] 59 06 [2] 45 01 [2] 59 2e }

  condition:
    any of them
}