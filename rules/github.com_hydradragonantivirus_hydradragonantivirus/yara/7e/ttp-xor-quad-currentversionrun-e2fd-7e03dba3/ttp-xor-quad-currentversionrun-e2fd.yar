rule TTP_XOR_QUAD_CurrentVersionRun_e2fd {
  strings:
    $key_e2fd = { b1 92 [2] 95 9c [2] be b0 [2] 90 92 [2] 84 89 [2] 8b 93 [2] 95 8e [2] 97 8f [2] 8c 89 [2] 90 8e [2] 8c a1 }

  condition:
    any of them
}