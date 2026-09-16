rule TTP_XOR_QUAD_CurrentVersionRun_f0e3 {
  strings:
    $key_f0e3 = { a3 8c [2] 87 82 [2] ac ae [2] 82 8c [2] 96 97 [2] 99 8d [2] 87 90 [2] 85 91 [2] 9e 97 [2] 82 90 [2] 9e bf }

  condition:
    any of them
}