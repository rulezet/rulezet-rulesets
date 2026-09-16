rule TTP_XOR_QUAD_CurrentVersionRun_5fe2 {
  strings:
    $key_5fe2 = { 0c 8d [2] 28 83 [2] 03 af [2] 2d 8d [2] 39 96 [2] 36 8c [2] 28 91 [2] 2a 90 [2] 31 96 [2] 2d 91 [2] 31 be }

  condition:
    any of them
}