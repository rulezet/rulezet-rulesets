rule TTP_XOR_QUAD_CurrentVersionRun_0963 {
  strings:
    $key_0963 = { 5a 0c [2] 7e 02 [2] 55 2e [2] 7b 0c [2] 6f 17 [2] 60 0d [2] 7e 10 [2] 7c 11 [2] 67 17 [2] 7b 10 [2] 67 3f }

  condition:
    any of them
}