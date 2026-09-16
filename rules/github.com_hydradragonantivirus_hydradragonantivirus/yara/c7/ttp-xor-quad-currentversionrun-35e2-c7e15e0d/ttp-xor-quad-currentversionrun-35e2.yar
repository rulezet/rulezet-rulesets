rule TTP_XOR_QUAD_CurrentVersionRun_35e2 {
  strings:
    $key_35e2 = { 66 8d [2] 42 83 [2] 69 af [2] 47 8d [2] 53 96 [2] 5c 8c [2] 42 91 [2] 40 90 [2] 5b 96 [2] 47 91 [2] 5b be }

  condition:
    any of them
}