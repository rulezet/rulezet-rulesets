rule TTP_XOR_QUAD_CurrentVersionRun_2ce2 {
  strings:
    $key_2ce2 = { 7f 8d [2] 5b 83 [2] 70 af [2] 5e 8d [2] 4a 96 [2] 45 8c [2] 5b 91 [2] 59 90 [2] 42 96 [2] 5e 91 [2] 42 be }

  condition:
    any of them
}