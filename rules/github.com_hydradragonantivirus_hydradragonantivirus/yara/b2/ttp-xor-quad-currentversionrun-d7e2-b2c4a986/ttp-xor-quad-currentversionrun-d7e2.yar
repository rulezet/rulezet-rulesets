rule TTP_XOR_QUAD_CurrentVersionRun_d7e2 {
  strings:
    $key_d7e2 = { 84 8d [2] a0 83 [2] 8b af [2] a5 8d [2] b1 96 [2] be 8c [2] a0 91 [2] a2 90 [2] b9 96 [2] a5 91 [2] b9 be }

  condition:
    any of them
}