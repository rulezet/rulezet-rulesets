rule TTP_XOR_QUAD_CurrentVersionRun_5de3 {
  strings:
    $key_5de3 = { 0e 8c [2] 2a 82 [2] 01 ae [2] 2f 8c [2] 3b 97 [2] 34 8d [2] 2a 90 [2] 28 91 [2] 33 97 [2] 2f 90 [2] 33 bf }

  condition:
    any of them
}