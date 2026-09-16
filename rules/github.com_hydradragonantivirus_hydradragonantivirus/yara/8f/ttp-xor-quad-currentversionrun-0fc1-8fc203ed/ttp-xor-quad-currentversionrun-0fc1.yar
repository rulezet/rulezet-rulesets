rule TTP_XOR_QUAD_CurrentVersionRun_0fc1 {
  strings:
    $key_0fc1 = { 5c ae [2] 78 a0 [2] 53 8c [2] 7d ae [2] 69 b5 [2] 66 af [2] 78 b2 [2] 7a b3 [2] 61 b5 [2] 7d b2 [2] 61 9d }

  condition:
    any of them
}