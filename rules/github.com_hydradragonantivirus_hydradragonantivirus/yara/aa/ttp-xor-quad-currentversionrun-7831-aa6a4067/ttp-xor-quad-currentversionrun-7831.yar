rule TTP_XOR_QUAD_CurrentVersionRun_7831 {
  strings:
    $key_7831 = { 2b 5e [2] 0f 50 [2] 24 7c [2] 0a 5e [2] 1e 45 [2] 11 5f [2] 0f 42 [2] 0d 43 [2] 16 45 [2] 0a 42 [2] 16 6d }

  condition:
    any of them
}