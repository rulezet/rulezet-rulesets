rule TTP_XOR_QUAD_CurrentVersionRun_3731 {
  strings:
    $key_3731 = { 64 5e [2] 40 50 [2] 6b 7c [2] 45 5e [2] 51 45 [2] 5e 5f [2] 40 42 [2] 42 43 [2] 59 45 [2] 45 42 [2] 59 6d }

  condition:
    any of them
}