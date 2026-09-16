rule TTP_XOR_QUAD_CurrentVersionRun_78e3 {
  strings:
    $key_78e3 = { 2b 8c [2] 0f 82 [2] 24 ae [2] 0a 8c [2] 1e 97 [2] 11 8d [2] 0f 90 [2] 0d 91 [2] 16 97 [2] 0a 90 [2] 16 bf }

  condition:
    any of them
}