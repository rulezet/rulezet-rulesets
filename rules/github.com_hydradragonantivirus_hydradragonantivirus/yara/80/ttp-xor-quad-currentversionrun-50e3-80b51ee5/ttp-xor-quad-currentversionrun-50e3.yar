rule TTP_XOR_QUAD_CurrentVersionRun_50e3 {
  strings:
    $key_50e3 = { 03 8c [2] 27 82 [2] 0c ae [2] 22 8c [2] 36 97 [2] 39 8d [2] 27 90 [2] 25 91 [2] 3e 97 [2] 22 90 [2] 3e bf }

  condition:
    any of them
}