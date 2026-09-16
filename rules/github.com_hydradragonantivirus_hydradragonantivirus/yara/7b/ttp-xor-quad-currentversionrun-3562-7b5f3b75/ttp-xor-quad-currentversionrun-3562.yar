rule TTP_XOR_QUAD_CurrentVersionRun_3562 {
  strings:
    $key_3562 = { 66 0d [2] 42 03 [2] 69 2f [2] 47 0d [2] 53 16 [2] 5c 0c [2] 42 11 [2] 40 10 [2] 5b 16 [2] 47 11 [2] 5b 3e }

  condition:
    any of them
}