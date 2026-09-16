rule TTP_XOR_QUAD_CurrentVersionRun_cce2 {
  strings:
    $key_cce2 = { 9f 8d [2] bb 83 [2] 90 af [2] be 8d [2] aa 96 [2] a5 8c [2] bb 91 [2] b9 90 [2] a2 96 [2] be 91 [2] a2 be }

  condition:
    any of them
}