rule TTP_XOR_QUAD_CurrentVersionRun_1ee2 {
  strings:
    $key_1ee2 = { 4d 8d [2] 69 83 [2] 42 af [2] 6c 8d [2] 78 96 [2] 77 8c [2] 69 91 [2] 6b 90 [2] 70 96 [2] 6c 91 [2] 70 be }

  condition:
    any of them
}