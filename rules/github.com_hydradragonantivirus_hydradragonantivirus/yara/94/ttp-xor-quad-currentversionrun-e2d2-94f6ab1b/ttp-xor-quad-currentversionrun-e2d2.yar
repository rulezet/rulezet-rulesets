rule TTP_XOR_QUAD_CurrentVersionRun_e2d2 {
  strings:
    $key_e2d2 = { b1 bd [2] 95 b3 [2] be 9f [2] 90 bd [2] 84 a6 [2] 8b bc [2] 95 a1 [2] 97 a0 [2] 8c a6 [2] 90 a1 [2] 8c 8e }

  condition:
    any of them
}