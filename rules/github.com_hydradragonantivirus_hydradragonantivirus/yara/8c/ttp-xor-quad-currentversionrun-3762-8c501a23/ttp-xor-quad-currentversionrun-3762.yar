rule TTP_XOR_QUAD_CurrentVersionRun_3762 {
  strings:
    $key_3762 = { 64 0d [2] 40 03 [2] 6b 2f [2] 45 0d [2] 51 16 [2] 5e 0c [2] 40 11 [2] 42 10 [2] 59 16 [2] 45 11 [2] 59 3e }

  condition:
    any of them
}