rule TTP_XOR_QUAD_CurrentVersionRun_2412 {
  strings:
    $key_2412 = { 77 7d [2] 53 73 [2] 78 5f [2] 56 7d [2] 42 66 [2] 4d 7c [2] 53 61 [2] 51 60 [2] 4a 66 [2] 56 61 [2] 4a 4e }

  condition:
    any of them
}