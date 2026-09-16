rule TTP_XOR_QUAD_CurrentVersionRun_20e2 {
  strings:
    $key_20e2 = { 73 8d [2] 57 83 [2] 7c af [2] 52 8d [2] 46 96 [2] 49 8c [2] 57 91 [2] 55 90 [2] 4e 96 [2] 52 91 [2] 4e be }

  condition:
    any of them
}