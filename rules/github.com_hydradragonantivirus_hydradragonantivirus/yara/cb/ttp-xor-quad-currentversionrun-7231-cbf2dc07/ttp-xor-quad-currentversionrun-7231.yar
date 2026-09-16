rule TTP_XOR_QUAD_CurrentVersionRun_7231 {
  strings:
    $key_7231 = { 21 5e [2] 05 50 [2] 2e 7c [2] 00 5e [2] 14 45 [2] 1b 5f [2] 05 42 [2] 07 43 [2] 1c 45 [2] 00 42 [2] 1c 6d }

  condition:
    any of them
}