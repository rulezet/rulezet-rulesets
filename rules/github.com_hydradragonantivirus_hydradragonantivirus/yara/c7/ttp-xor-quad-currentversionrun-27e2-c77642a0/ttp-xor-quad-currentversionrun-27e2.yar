rule TTP_XOR_QUAD_CurrentVersionRun_27e2 {
  strings:
    $key_27e2 = { 74 8d [2] 50 83 [2] 7b af [2] 55 8d [2] 41 96 [2] 4e 8c [2] 50 91 [2] 52 90 [2] 49 96 [2] 55 91 [2] 49 be }

  condition:
    any of them
}