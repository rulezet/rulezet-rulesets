rule TTP_XOR_QUAD_CurrentVersionRun_7ce3 {
  strings:
    $key_7ce3 = { 2f 8c [2] 0b 82 [2] 20 ae [2] 0e 8c [2] 1a 97 [2] 15 8d [2] 0b 90 [2] 09 91 [2] 12 97 [2] 0e 90 [2] 12 bf }

  condition:
    any of them
}