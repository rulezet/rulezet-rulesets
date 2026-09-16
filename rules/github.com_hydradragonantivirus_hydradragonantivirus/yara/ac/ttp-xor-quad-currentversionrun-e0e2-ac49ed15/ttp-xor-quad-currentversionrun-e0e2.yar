rule TTP_XOR_QUAD_CurrentVersionRun_e0e2 {
  strings:
    $key_e0e2 = { b3 8d [2] 97 83 [2] bc af [2] 92 8d [2] 86 96 [2] 89 8c [2] 97 91 [2] 95 90 [2] 8e 96 [2] 92 91 [2] 8e be }

  condition:
    any of them
}