rule TTP_XOR_QUAD_CurrentVersionRun_3831 {
  strings:
    $key_3831 = { 6b 5e [2] 4f 50 [2] 64 7c [2] 4a 5e [2] 5e 45 [2] 51 5f [2] 4f 42 [2] 4d 43 [2] 56 45 [2] 4a 42 [2] 56 6d }

  condition:
    any of them
}