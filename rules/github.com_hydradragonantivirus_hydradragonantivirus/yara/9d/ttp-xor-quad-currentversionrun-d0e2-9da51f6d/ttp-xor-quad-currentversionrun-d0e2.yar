rule TTP_XOR_QUAD_CurrentVersionRun_d0e2 {
  strings:
    $key_d0e2 = { 83 8d [2] a7 83 [2] 8c af [2] a2 8d [2] b6 96 [2] b9 8c [2] a7 91 [2] a5 90 [2] be 96 [2] a2 91 [2] be be }

  condition:
    any of them
}