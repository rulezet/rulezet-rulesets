rule TTP_XOR_QUAD_CurrentVersionRun_7ee3 {
  strings:
    $key_7ee3 = { 2d 8c [2] 09 82 [2] 22 ae [2] 0c 8c [2] 18 97 [2] 17 8d [2] 09 90 [2] 0b 91 [2] 10 97 [2] 0c 90 [2] 10 bf }

  condition:
    any of them
}