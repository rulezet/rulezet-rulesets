rule TTP_XOR_QUAD_CurrentVersionRun_4be3 {
  strings:
    $key_4be3 = { 18 8c [2] 3c 82 [2] 17 ae [2] 39 8c [2] 2d 97 [2] 22 8d [2] 3c 90 [2] 3e 91 [2] 25 97 [2] 39 90 [2] 25 bf }

  condition:
    any of them
}