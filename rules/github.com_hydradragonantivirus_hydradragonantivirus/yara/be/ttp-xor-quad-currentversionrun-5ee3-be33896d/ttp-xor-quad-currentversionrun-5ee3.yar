rule TTP_XOR_QUAD_CurrentVersionRun_5ee3 {
  strings:
    $key_5ee3 = { 0d 8c [2] 29 82 [2] 02 ae [2] 2c 8c [2] 38 97 [2] 37 8d [2] 29 90 [2] 2b 91 [2] 30 97 [2] 2c 90 [2] 30 bf }

  condition:
    any of them
}