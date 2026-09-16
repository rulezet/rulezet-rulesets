rule TTP_XOR_QUAD_CurrentVersionRun_d831 {
  strings:
    $key_d831 = { 8b 5e [2] af 50 [2] 84 7c [2] aa 5e [2] be 45 [2] b1 5f [2] af 42 [2] ad 43 [2] b6 45 [2] aa 42 [2] b6 6d }

  condition:
    any of them
}