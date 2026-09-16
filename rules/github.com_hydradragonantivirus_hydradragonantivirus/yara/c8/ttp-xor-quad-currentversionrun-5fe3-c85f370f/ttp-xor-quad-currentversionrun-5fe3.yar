rule TTP_XOR_QUAD_CurrentVersionRun_5fe3 {
  strings:
    $key_5fe3 = { 0c 8c [2] 28 82 [2] 03 ae [2] 2d 8c [2] 39 97 [2] 36 8d [2] 28 90 [2] 2a 91 [2] 31 97 [2] 2d 90 [2] 31 bf }

  condition:
    any of them
}