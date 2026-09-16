rule TTP_XOR_QUAD_CurrentVersionRun_6cdc {
  strings:
    $key_6cdc = { 3f b3 [2] 1b bd [2] 30 91 [2] 1e b3 [2] 0a a8 [2] 05 b2 [2] 1b af [2] 19 ae [2] 02 a8 [2] 1e af [2] 02 80 }

  condition:
    any of them
}