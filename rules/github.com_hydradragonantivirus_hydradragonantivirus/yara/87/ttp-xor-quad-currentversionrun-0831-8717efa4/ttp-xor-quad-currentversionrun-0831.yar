rule TTP_XOR_QUAD_CurrentVersionRun_0831 {
  strings:
    $key_0831 = { 5b 5e [2] 7f 50 [2] 54 7c [2] 7a 5e [2] 6e 45 [2] 61 5f [2] 7f 42 [2] 7d 43 [2] 66 45 [2] 7a 42 [2] 66 6d }

  condition:
    any of them
}