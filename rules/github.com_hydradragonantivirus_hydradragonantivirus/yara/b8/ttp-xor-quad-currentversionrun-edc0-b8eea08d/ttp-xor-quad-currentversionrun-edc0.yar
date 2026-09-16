rule TTP_XOR_QUAD_CurrentVersionRun_edc0 {
  strings:
    $key_edc0 = { be af [2] 9a a1 [2] b1 8d [2] 9f af [2] 8b b4 [2] 84 ae [2] 9a b3 [2] 98 b2 [2] 83 b4 [2] 9f b3 [2] 83 9c }

  condition:
    any of them
}