rule TTP_XOR_QUAD_CurrentVersionRun_7ee2 {
  strings:
    $key_7ee2 = { 2d 8d [2] 09 83 [2] 22 af [2] 0c 8d [2] 18 96 [2] 17 8c [2] 09 91 [2] 0b 90 [2] 10 96 [2] 0c 91 [2] 10 be }

  condition:
    any of them
}