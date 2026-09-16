rule TTP_XOR_QUAD_CurrentVersionRun_3722 {
  strings:
    $key_3722 = { 64 4d [2] 40 43 [2] 6b 6f [2] 45 4d [2] 51 56 [2] 5e 4c [2] 40 51 [2] 42 50 [2] 59 56 [2] 45 51 [2] 59 7e }

  condition:
    any of them
}