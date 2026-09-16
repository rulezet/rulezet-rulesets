rule TTP_XOR_QUAD_CurrentVersionRun_0131 {
  strings:
    $key_0131 = { 52 5e [2] 76 50 [2] 5d 7c [2] 73 5e [2] 67 45 [2] 68 5f [2] 76 42 [2] 74 43 [2] 6f 45 [2] 73 42 [2] 6f 6d }

  condition:
    any of them
}