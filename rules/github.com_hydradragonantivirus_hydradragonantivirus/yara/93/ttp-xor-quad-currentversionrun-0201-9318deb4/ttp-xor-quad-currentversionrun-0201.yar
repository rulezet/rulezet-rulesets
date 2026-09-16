rule TTP_XOR_QUAD_CurrentVersionRun_0201 {
  strings:
    $key_0201 = { 51 6e [2] 75 60 [2] 5e 4c [2] 70 6e [2] 64 75 [2] 6b 6f [2] 75 72 [2] 77 73 [2] 6c 75 [2] 70 72 [2] 6c 5d }

  condition:
    any of them
}