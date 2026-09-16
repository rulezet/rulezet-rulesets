rule TTP_XOR_QUAD_CurrentVersionRun_fbe2 {
  strings:
    $key_fbe2 = { a8 8d [2] 8c 83 [2] a7 af [2] 89 8d [2] 9d 96 [2] 92 8c [2] 8c 91 [2] 8e 90 [2] 95 96 [2] 89 91 [2] 95 be }

  condition:
    any of them
}