rule TTP_XOR_QUAD_CurrentVersionRun_0212 {
  strings:
    $key_0212 = { 51 7d [2] 75 73 [2] 5e 5f [2] 70 7d [2] 64 66 [2] 6b 7c [2] 75 61 [2] 77 60 [2] 6c 66 [2] 70 61 [2] 6c 4e }

  condition:
    any of them
}