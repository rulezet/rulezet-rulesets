rule TTP_XOR_QUAD_CurrentVersionRun_60e3 {
  strings:
    $key_60e3 = { 33 8c [2] 17 82 [2] 3c ae [2] 12 8c [2] 06 97 [2] 09 8d [2] 17 90 [2] 15 91 [2] 0e 97 [2] 12 90 [2] 0e bf }

  condition:
    any of them
}