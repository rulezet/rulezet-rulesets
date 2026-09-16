rule TTP_XOR_QUAD_CurrentVersionRun_44e3 {
  strings:
    $key_44e3 = { 17 8c [2] 33 82 [2] 18 ae [2] 36 8c [2] 22 97 [2] 2d 8d [2] 33 90 [2] 31 91 [2] 2a 97 [2] 36 90 [2] 2a bf }

  condition:
    any of them
}