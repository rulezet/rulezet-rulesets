rule TTP_XOR_QUAD_CurrentVersionRun_67e3 {
  strings:
    $key_67e3 = { 34 8c [2] 10 82 [2] 3b ae [2] 15 8c [2] 01 97 [2] 0e 8d [2] 10 90 [2] 12 91 [2] 09 97 [2] 15 90 [2] 09 bf }

  condition:
    any of them
}