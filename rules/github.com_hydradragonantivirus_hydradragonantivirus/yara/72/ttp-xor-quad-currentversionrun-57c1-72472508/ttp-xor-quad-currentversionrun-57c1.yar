rule TTP_XOR_QUAD_CurrentVersionRun_57c1 {
  strings:
    $key_57c1 = { 04 ae [2] 20 a0 [2] 0b 8c [2] 25 ae [2] 31 b5 [2] 3e af [2] 20 b2 [2] 22 b3 [2] 39 b5 [2] 25 b2 [2] 39 9d }

  condition:
    any of them
}