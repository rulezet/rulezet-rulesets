rule TTP_XOR_QUAD_CurrentVersionRun_1fe3 {
  strings:
    $key_1fe3 = { 4c 8c [2] 68 82 [2] 43 ae [2] 6d 8c [2] 79 97 [2] 76 8d [2] 68 90 [2] 6a 91 [2] 71 97 [2] 6d 90 [2] 71 bf }

  condition:
    any of them
}