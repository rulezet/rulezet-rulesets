rule TTP_XOR_QUAD_CurrentVersionRun_0233 {
  strings:
    $key_0233 = { 51 5c [2] 75 52 [2] 5e 7e [2] 70 5c [2] 64 47 [2] 6b 5d [2] 75 40 [2] 77 41 [2] 6c 47 [2] 70 40 [2] 6c 6f }

  condition:
    any of them
}