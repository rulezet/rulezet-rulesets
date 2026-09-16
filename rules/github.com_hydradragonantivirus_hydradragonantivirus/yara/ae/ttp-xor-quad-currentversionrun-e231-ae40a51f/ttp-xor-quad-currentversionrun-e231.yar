rule TTP_XOR_QUAD_CurrentVersionRun_e231 {
  strings:
    $key_e231 = { b1 5e [2] 95 50 [2] be 7c [2] 90 5e [2] 84 45 [2] 8b 5f [2] 95 42 [2] 97 43 [2] 8c 45 [2] 90 42 [2] 8c 6d }

  condition:
    any of them
}