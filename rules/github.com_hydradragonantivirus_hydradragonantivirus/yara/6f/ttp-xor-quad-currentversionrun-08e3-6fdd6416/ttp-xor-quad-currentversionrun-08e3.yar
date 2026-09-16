rule TTP_XOR_QUAD_CurrentVersionRun_08e3 {
  strings:
    $key_08e3 = { 5b 8c [2] 7f 82 [2] 54 ae [2] 7a 8c [2] 6e 97 [2] 61 8d [2] 7f 90 [2] 7d 91 [2] 66 97 [2] 7a 90 [2] 66 bf }

  condition:
    any of them
}