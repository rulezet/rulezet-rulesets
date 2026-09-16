rule TTP_XOR_QUAD_CurrentVersionRun_eadd {
  strings:
    $key_eadd = { b9 b2 [2] 9d bc [2] b6 90 [2] 98 b2 [2] 8c a9 [2] 83 b3 [2] 9d ae [2] 9f af [2] 84 a9 [2] 98 ae [2] 84 81 }

  condition:
    any of them
}