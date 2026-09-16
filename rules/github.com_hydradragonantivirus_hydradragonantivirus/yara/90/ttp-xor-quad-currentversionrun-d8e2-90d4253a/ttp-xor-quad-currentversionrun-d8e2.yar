rule TTP_XOR_QUAD_CurrentVersionRun_d8e2 {
  strings:
    $key_d8e2 = { 8b 8d [2] af 83 [2] 84 af [2] aa 8d [2] be 96 [2] b1 8c [2] af 91 [2] ad 90 [2] b6 96 [2] aa 91 [2] b6 be }

  condition:
    any of them
}