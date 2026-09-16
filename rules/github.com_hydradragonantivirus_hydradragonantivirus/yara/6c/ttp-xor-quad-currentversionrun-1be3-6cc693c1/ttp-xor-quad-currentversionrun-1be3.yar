rule TTP_XOR_QUAD_CurrentVersionRun_1be3 {
  strings:
    $key_1be3 = { 48 8c [2] 6c 82 [2] 47 ae [2] 69 8c [2] 7d 97 [2] 72 8d [2] 6c 90 [2] 6e 91 [2] 75 97 [2] 69 90 [2] 75 bf }

  condition:
    any of them
}