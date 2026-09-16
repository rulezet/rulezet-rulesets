rule TTP_XOR_QUAD_CurrentVersionRun_29c0 {
  strings:
    $key_29c0 = { 7a af [2] 5e a1 [2] 75 8d [2] 5b af [2] 4f b4 [2] 40 ae [2] 5e b3 [2] 5c b2 [2] 47 b4 [2] 5b b3 [2] 47 9c }

  condition:
    any of them
}