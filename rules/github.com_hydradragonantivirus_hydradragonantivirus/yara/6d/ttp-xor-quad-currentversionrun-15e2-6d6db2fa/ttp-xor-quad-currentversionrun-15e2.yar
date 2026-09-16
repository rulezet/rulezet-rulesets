rule TTP_XOR_QUAD_CurrentVersionRun_15e2 {
  strings:
    $key_15e2 = { 46 8d [2] 62 83 [2] 49 af [2] 67 8d [2] 73 96 [2] 7c 8c [2] 62 91 [2] 60 90 [2] 7b 96 [2] 67 91 [2] 7b be }

  condition:
    any of them
}