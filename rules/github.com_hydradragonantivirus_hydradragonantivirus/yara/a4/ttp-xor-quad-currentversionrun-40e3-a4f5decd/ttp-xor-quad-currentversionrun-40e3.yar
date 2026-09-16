rule TTP_XOR_QUAD_CurrentVersionRun_40e3 {
  strings:
    $key_40e3 = { 13 8c [2] 37 82 [2] 1c ae [2] 32 8c [2] 26 97 [2] 29 8d [2] 37 90 [2] 35 91 [2] 2e 97 [2] 32 90 [2] 2e bf }

  condition:
    any of them
}