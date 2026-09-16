rule TTP_XOR_QUAD_CurrentVersionRun_0fc0 {
  strings:
    $key_0fc0 = { 5c af [2] 78 a1 [2] 53 8d [2] 7d af [2] 69 b4 [2] 66 ae [2] 78 b3 [2] 7a b2 [2] 61 b4 [2] 7d b3 [2] 61 9c }

  condition:
    any of them
}