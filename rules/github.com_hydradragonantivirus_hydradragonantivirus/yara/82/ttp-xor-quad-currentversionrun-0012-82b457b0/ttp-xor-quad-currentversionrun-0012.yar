rule TTP_XOR_QUAD_CurrentVersionRun_0012 {
  strings:
    $key_0012 = { 53 7d [2] 77 73 [2] 5c 5f [2] 72 7d [2] 66 66 [2] 69 7c [2] 77 61 [2] 75 60 [2] 6e 66 [2] 72 61 [2] 6e 4e }

  condition:
    any of them
}