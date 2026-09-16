rule TTP_XOR_QUAD_CurrentVersionRun_c3e2 {
  strings:
    $key_c3e2 = { 90 8d [2] b4 83 [2] 9f af [2] b1 8d [2] a5 96 [2] aa 8c [2] b4 91 [2] b6 90 [2] ad 96 [2] b1 91 [2] ad be }

  condition:
    any of them
}