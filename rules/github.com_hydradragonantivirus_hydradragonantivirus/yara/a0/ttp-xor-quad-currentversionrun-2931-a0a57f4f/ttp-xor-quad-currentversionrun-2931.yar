rule TTP_XOR_QUAD_CurrentVersionRun_2931 {
  strings:
    $key_2931 = { 7a 5e [2] 5e 50 [2] 75 7c [2] 5b 5e [2] 4f 45 [2] 40 5f [2] 5e 42 [2] 5c 43 [2] 47 45 [2] 5b 42 [2] 47 6d }

  condition:
    any of them
}