rule TTP_XOR_QUAD_CurrentVersionRun_1e12 {
  strings:
    $key_1e12 = { 4d 7d [2] 69 73 [2] 42 5f [2] 6c 7d [2] 78 66 [2] 77 7c [2] 69 61 [2] 6b 60 [2] 70 66 [2] 6c 61 [2] 70 4e }

  condition:
    any of them
}