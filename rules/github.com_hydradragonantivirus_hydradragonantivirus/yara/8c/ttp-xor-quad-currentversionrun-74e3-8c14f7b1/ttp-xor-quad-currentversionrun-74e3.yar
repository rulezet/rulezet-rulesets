rule TTP_XOR_QUAD_CurrentVersionRun_74e3 {
  strings:
    $key_74e3 = { 27 8c [2] 03 82 [2] 28 ae [2] 06 8c [2] 12 97 [2] 1d 8d [2] 03 90 [2] 01 91 [2] 1a 97 [2] 06 90 [2] 1a bf }

  condition:
    any of them
}