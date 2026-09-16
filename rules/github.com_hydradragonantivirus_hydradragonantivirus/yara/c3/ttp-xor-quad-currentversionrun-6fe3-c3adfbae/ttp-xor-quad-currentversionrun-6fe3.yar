rule TTP_XOR_QUAD_CurrentVersionRun_6fe3 {
  strings:
    $key_6fe3 = { 3c 8c [2] 18 82 [2] 33 ae [2] 1d 8c [2] 09 97 [2] 06 8d [2] 18 90 [2] 1a 91 [2] 01 97 [2] 1d 90 [2] 01 bf }

  condition:
    any of them
}