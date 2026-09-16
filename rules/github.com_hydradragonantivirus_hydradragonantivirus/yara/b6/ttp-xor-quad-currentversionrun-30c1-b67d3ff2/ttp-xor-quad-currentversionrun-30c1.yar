rule TTP_XOR_QUAD_CurrentVersionRun_30c1 {
  strings:
    $key_30c1 = { 63 ae [2] 47 a0 [2] 6c 8c [2] 42 ae [2] 56 b5 [2] 59 af [2] 47 b2 [2] 45 b3 [2] 5e b5 [2] 42 b2 [2] 5e 9d }

  condition:
    any of them
}