rule TTP_XOR_QUAD_CurrentVersionRun_11e2 {
  strings:
    $key_11e2 = { 42 8d [2] 66 83 [2] 4d af [2] 63 8d [2] 77 96 [2] 78 8c [2] 66 91 [2] 64 90 [2] 7f 96 [2] 63 91 [2] 7f be }

  condition:
    any of them
}