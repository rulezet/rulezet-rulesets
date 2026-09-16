rule TTP_XOR_QUAD_CurrentVersionRun_1e32 {
  strings:
    $key_1e32 = { 4d 5d [2] 69 53 [2] 42 7f [2] 6c 5d [2] 78 46 [2] 77 5c [2] 69 41 [2] 6b 40 [2] 70 46 [2] 6c 41 [2] 70 6e }

  condition:
    any of them
}