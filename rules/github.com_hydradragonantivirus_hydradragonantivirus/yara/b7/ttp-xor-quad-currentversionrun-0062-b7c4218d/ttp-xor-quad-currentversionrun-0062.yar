rule TTP_XOR_QUAD_CurrentVersionRun_0062 {
  strings:
    $key_0062 = { 53 0d [2] 77 03 [2] 5c 2f [2] 72 0d [2] 66 16 [2] 69 0c [2] 77 11 [2] 75 10 [2] 6e 16 [2] 72 11 [2] 6e 3e }

  condition:
    any of them
}