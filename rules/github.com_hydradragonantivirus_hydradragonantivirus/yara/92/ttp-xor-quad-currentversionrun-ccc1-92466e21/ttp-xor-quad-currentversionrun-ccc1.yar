rule TTP_XOR_QUAD_CurrentVersionRun_ccc1 {
  strings:
    $key_ccc1 = { 9f ae [2] bb a0 [2] 90 8c [2] be ae [2] aa b5 [2] a5 af [2] bb b2 [2] b9 b3 [2] a2 b5 [2] be b2 [2] a2 9d }

  condition:
    any of them
}