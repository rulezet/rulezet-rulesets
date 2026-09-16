rule TTP_XOR_QUAD_CurrentVersionRun_d0a2 {
  strings:
    $key_d0a2 = { 83 cd [2] a7 c3 [2] 8c ef [2] a2 cd [2] b6 d6 [2] b9 cc [2] a7 d1 [2] a5 d0 [2] be d6 [2] a2 d1 [2] be fe }

  condition:
    any of them
}