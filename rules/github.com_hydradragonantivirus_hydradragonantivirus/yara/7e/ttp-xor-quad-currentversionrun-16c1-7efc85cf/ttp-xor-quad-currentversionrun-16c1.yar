rule TTP_XOR_QUAD_CurrentVersionRun_16c1 {
  strings:
    $key_16c1 = { 45 ae [2] 61 a0 [2] 4a 8c [2] 64 ae [2] 70 b5 [2] 7f af [2] 61 b2 [2] 63 b3 [2] 78 b5 [2] 64 b2 [2] 78 9d }

  condition:
    any of them
}