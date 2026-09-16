rule TTP_XOR_QUAD_CurrentVersionRun_0231 {
  strings:
    $key_0231 = { 51 5e [2] 75 50 [2] 5e 7c [2] 70 5e [2] 64 45 [2] 6b 5f [2] 75 42 [2] 77 43 [2] 6c 45 [2] 70 42 [2] 6c 6d }

  condition:
    any of them
}