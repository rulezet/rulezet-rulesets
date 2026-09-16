rule TTP_XOR_QUAD_CurrentVersionRun_79e3 {
  strings:
    $key_79e3 = { 2a 8c [2] 0e 82 [2] 25 ae [2] 0b 8c [2] 1f 97 [2] 10 8d [2] 0e 90 [2] 0c 91 [2] 17 97 [2] 0b 90 [2] 17 bf }

  condition:
    any of them
}