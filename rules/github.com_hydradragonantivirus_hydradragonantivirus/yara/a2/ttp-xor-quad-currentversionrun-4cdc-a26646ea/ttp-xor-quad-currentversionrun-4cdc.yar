rule TTP_XOR_QUAD_CurrentVersionRun_4cdc {
  strings:
    $key_4cdc = { 1f b3 [2] 3b bd [2] 10 91 [2] 3e b3 [2] 2a a8 [2] 25 b2 [2] 3b af [2] 39 ae [2] 22 a8 [2] 3e af [2] 22 80 }

  condition:
    any of them
}