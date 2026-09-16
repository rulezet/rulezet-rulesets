rule TTP_XOR_QUAD_CurrentVersionRun_7cdc {
  strings:
    $key_7cdc = { 2f b3 [2] 0b bd [2] 20 91 [2] 0e b3 [2] 1a a8 [2] 15 b2 [2] 0b af [2] 09 ae [2] 12 a8 [2] 0e af [2] 12 80 }

  condition:
    any of them
}