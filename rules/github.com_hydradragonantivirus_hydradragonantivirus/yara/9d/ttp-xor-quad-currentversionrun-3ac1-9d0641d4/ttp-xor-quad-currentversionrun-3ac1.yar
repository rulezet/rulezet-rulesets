rule TTP_XOR_QUAD_CurrentVersionRun_3ac1 {
  strings:
    $key_3ac1 = { 69 ae [2] 4d a0 [2] 66 8c [2] 48 ae [2] 5c b5 [2] 53 af [2] 4d b2 [2] 4f b3 [2] 54 b5 [2] 48 b2 [2] 54 9d }

  condition:
    any of them
}