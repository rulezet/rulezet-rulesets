rule TTP_XOR_QUAD_CurrentVersionRun_3712 {
  strings:
    $key_3712 = { 64 7d [2] 40 73 [2] 6b 5f [2] 45 7d [2] 51 66 [2] 5e 7c [2] 40 61 [2] 42 60 [2] 59 66 [2] 45 61 [2] 59 4e }

  condition:
    any of them
}