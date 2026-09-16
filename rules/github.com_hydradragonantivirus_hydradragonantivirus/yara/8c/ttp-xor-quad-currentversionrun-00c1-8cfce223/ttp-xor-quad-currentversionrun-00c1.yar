rule TTP_XOR_QUAD_CurrentVersionRun_00c1 {
  strings:
    $key_00c1 = { 53 ae [2] 77 a0 [2] 5c 8c [2] 72 ae [2] 66 b5 [2] 69 af [2] 77 b2 [2] 75 b3 [2] 6e b5 [2] 72 b2 [2] 6e 9d }

  condition:
    any of them
}