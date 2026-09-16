rule TTP_XOR_QUAD_CurrentVersionRun_c431 {
  strings:
    $key_c431 = { 97 5e [2] b3 50 [2] 98 7c [2] b6 5e [2] a2 45 [2] ad 5f [2] b3 42 [2] b1 43 [2] aa 45 [2] b6 42 [2] aa 6d }

  condition:
    any of them
}