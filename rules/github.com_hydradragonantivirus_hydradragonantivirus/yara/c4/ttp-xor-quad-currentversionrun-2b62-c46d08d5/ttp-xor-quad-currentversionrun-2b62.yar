rule TTP_XOR_QUAD_CurrentVersionRun_2b62 {
  strings:
    $key_2b62 = { 78 0d [2] 5c 03 [2] 77 2f [2] 59 0d [2] 4d 16 [2] 42 0c [2] 5c 11 [2] 5e 10 [2] 45 16 [2] 59 11 [2] 45 3e }

  condition:
    any of them
}