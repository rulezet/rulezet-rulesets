rule TTP_XOR_QUAD_CurrentVersionRun_1ace {
  strings:
    $key_1ace = { 49 a1 [2] 6d af [2] 46 83 [2] 68 a1 [2] 7c ba [2] 73 a0 [2] 6d bd [2] 6f bc [2] 74 ba [2] 68 bd [2] 74 92 }

  condition:
    any of them
}