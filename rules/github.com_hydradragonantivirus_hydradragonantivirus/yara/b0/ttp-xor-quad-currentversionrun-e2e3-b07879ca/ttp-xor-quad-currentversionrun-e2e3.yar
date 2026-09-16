rule TTP_XOR_QUAD_CurrentVersionRun_e2e3 {
  strings:
    $key_e2e3 = { b1 8c [2] 95 82 [2] be ae [2] 90 8c [2] 84 97 [2] 8b 8d [2] 95 90 [2] 97 91 [2] 8c 97 [2] 90 90 [2] 8c bf }

  condition:
    any of them
}