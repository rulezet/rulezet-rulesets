rule TTP_XOR_QUAD_CurrentVersionRun_eddb {
  strings:
    $key_eddb = { be b4 [2] 9a ba [2] b1 96 [2] 9f b4 [2] 8b af [2] 84 b5 [2] 9a a8 [2] 98 a9 [2] 83 af [2] 9f a8 [2] 83 87 }

  condition:
    any of them
}