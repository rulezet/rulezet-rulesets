rule TTP_XOR_QUAD_CurrentVersionRun_4de3 {
  strings:
    $key_4de3 = { 1e 8c [2] 3a 82 [2] 11 ae [2] 3f 8c [2] 2b 97 [2] 24 8d [2] 3a 90 [2] 38 91 [2] 23 97 [2] 3f 90 [2] 23 bf }

  condition:
    any of them
}