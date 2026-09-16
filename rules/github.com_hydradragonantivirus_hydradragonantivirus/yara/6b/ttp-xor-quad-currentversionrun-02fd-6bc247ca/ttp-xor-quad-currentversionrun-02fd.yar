rule TTP_XOR_QUAD_CurrentVersionRun_02fd {
  strings:
    $key_02fd = { 51 92 [2] 75 9c [2] 5e b0 [2] 70 92 [2] 64 89 [2] 6b 93 [2] 75 8e [2] 77 8f [2] 6c 89 [2] 70 8e [2] 6c a1 }

  condition:
    any of them
}