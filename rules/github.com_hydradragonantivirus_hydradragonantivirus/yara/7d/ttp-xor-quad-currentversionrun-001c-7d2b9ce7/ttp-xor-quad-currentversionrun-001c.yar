rule TTP_XOR_QUAD_CurrentVersionRun_001c {
  strings:
    $key_001c = { 53 73 [2] 77 7d [2] 5c 51 [2] 72 73 [2] 66 68 [2] 69 72 [2] 77 6f [2] 75 6e [2] 6e 68 [2] 72 6f [2] 6e 40 }

  condition:
    any of them
}