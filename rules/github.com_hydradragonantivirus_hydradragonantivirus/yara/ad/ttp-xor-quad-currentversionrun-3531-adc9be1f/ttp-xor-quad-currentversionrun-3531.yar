rule TTP_XOR_QUAD_CurrentVersionRun_3531 {
  strings:
    $key_3531 = { 66 5e [2] 42 50 [2] 69 7c [2] 47 5e [2] 53 45 [2] 5c 5f [2] 42 42 [2] 40 43 [2] 5b 45 [2] 47 42 [2] 5b 6d }

  condition:
    any of them
}