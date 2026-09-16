rule TTP_XOR_QUAD_CurrentVersionRun_5ee2 {
  strings:
    $key_5ee2 = { 0d 8d [2] 29 83 [2] 02 af [2] 2c 8d [2] 38 96 [2] 37 8c [2] 29 91 [2] 2b 90 [2] 30 96 [2] 2c 91 [2] 30 be }

  condition:
    any of them
}