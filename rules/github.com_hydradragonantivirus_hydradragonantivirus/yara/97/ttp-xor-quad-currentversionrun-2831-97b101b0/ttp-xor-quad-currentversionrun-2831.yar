rule TTP_XOR_QUAD_CurrentVersionRun_2831 {
  strings:
    $key_2831 = { 7b 5e [2] 5f 50 [2] 74 7c [2] 5a 5e [2] 4e 45 [2] 41 5f [2] 5f 42 [2] 5d 43 [2] 46 45 [2] 5a 42 [2] 46 6d }

  condition:
    any of them
}