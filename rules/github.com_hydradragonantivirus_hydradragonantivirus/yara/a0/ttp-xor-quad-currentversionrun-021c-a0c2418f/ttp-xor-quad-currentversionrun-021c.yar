rule TTP_XOR_QUAD_CurrentVersionRun_021c {
  strings:
    $key_021c = { 51 73 [2] 75 7d [2] 5e 51 [2] 70 73 [2] 64 68 [2] 6b 72 [2] 75 6f [2] 77 6e [2] 6c 68 [2] 70 6f [2] 6c 40 }

  condition:
    any of them
}