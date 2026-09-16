rule TTP_XOR_QUAD_CurrentVersionRun_3231 {
  strings:
    $key_3231 = { 61 5e [2] 45 50 [2] 6e 7c [2] 40 5e [2] 54 45 [2] 5b 5f [2] 45 42 [2] 47 43 [2] 5c 45 [2] 40 42 [2] 5c 6d }

  condition:
    any of them
}