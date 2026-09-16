rule TTP_XOR_QUAD_CurrentVersionRun_2e31 {
  strings:
    $key_2e31 = { 7d 5e [2] 59 50 [2] 72 7c [2] 5c 5e [2] 48 45 [2] 47 5f [2] 59 42 [2] 5b 43 [2] 40 45 [2] 5c 42 [2] 40 6d }

  condition:
    any of them
}