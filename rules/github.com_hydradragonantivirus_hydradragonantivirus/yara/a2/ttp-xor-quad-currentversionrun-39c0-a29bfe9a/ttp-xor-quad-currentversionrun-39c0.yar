rule TTP_XOR_QUAD_CurrentVersionRun_39c0 {
  strings:
    $key_39c0 = { 6a af [2] 4e a1 [2] 65 8d [2] 4b af [2] 5f b4 [2] 50 ae [2] 4e b3 [2] 4c b2 [2] 57 b4 [2] 4b b3 [2] 57 9c }

  condition:
    any of them
}