rule TTP_XOR_QUAD_CurrentVersionRun_d6e2 {
  strings:
    $key_d6e2 = { 85 8d [2] a1 83 [2] 8a af [2] a4 8d [2] b0 96 [2] bf 8c [2] a1 91 [2] a3 90 [2] b8 96 [2] a4 91 [2] b8 be }

  condition:
    any of them
}