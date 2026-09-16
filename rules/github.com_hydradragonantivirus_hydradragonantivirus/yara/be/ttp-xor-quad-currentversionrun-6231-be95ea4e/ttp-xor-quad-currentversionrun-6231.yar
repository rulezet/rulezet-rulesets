rule TTP_XOR_QUAD_CurrentVersionRun_6231 {
  strings:
    $key_6231 = { 31 5e [2] 15 50 [2] 3e 7c [2] 10 5e [2] 04 45 [2] 0b 5f [2] 15 42 [2] 17 43 [2] 0c 45 [2] 10 42 [2] 0c 6d }

  condition:
    any of them
}