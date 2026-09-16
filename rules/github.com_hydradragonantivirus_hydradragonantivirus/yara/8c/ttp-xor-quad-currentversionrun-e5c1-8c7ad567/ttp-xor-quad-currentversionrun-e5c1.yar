rule TTP_XOR_QUAD_CurrentVersionRun_e5c1 {
  strings:
    $key_e5c1 = { b6 ae [2] 92 a0 [2] b9 8c [2] 97 ae [2] 83 b5 [2] 8c af [2] 92 b2 [2] 90 b3 [2] 8b b5 [2] 97 b2 [2] 8b 9d }

  condition:
    any of them
}