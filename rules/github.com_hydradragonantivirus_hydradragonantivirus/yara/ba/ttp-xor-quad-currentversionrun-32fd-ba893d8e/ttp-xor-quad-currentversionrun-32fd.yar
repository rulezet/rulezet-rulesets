rule TTP_XOR_QUAD_CurrentVersionRun_32fd {
  strings:
    $key_32fd = { 61 92 [2] 45 9c [2] 6e b0 [2] 40 92 [2] 54 89 [2] 5b 93 [2] 45 8e [2] 47 8f [2] 5c 89 [2] 40 8e [2] 5c a1 }

  condition:
    any of them
}