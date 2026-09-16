rule TTP_XOR_QUAD_CurrentVersionRun_20e3 {
  strings:
    $key_20e3 = { 73 8c [2] 57 82 [2] 7c ae [2] 52 8c [2] 46 97 [2] 49 8d [2] 57 90 [2] 55 91 [2] 4e 97 [2] 52 90 [2] 4e bf }

  condition:
    any of them
}