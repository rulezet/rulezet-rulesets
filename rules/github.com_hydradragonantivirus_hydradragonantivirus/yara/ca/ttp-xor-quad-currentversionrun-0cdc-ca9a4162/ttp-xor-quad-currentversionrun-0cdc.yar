rule TTP_XOR_QUAD_CurrentVersionRun_0cdc {
  strings:
    $key_0cdc = { 5f b3 [2] 7b bd [2] 50 91 [2] 7e b3 [2] 6a a8 [2] 65 b2 [2] 7b af [2] 79 ae [2] 62 a8 [2] 7e af [2] 62 80 }

  condition:
    any of them
}