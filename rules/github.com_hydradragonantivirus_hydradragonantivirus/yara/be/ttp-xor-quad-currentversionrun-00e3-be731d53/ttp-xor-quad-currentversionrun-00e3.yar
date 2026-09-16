rule TTP_XOR_QUAD_CurrentVersionRun_00e3 {
  strings:
    $key_00e3 = { 53 8c [2] 77 82 [2] 5c ae [2] 72 8c [2] 66 97 [2] 69 8d [2] 77 90 [2] 75 91 [2] 6e 97 [2] 72 90 [2] 6e bf }

  condition:
    any of them
}