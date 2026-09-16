rule TTP_XOR_QUAD_CurrentVersionRun_05c1 {
  strings:
    $key_05c1 = { 56 ae [2] 72 a0 [2] 59 8c [2] 77 ae [2] 63 b5 [2] 6c af [2] 72 b2 [2] 70 b3 [2] 6b b5 [2] 77 b2 [2] 6b 9d }

  condition:
    any of them
}