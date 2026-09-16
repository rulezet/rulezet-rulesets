rule TTP_XOR_QUAD_CurrentVersionRun_37e2 {
  strings:
    $key_37e2 = { 64 8d [2] 40 83 [2] 6b af [2] 45 8d [2] 51 96 [2] 5e 8c [2] 40 91 [2] 42 90 [2] 59 96 [2] 45 91 [2] 59 be }

  condition:
    any of them
}