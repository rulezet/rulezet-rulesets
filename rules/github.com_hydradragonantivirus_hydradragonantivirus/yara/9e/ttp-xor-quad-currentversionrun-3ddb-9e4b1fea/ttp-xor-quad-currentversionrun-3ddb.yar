rule TTP_XOR_QUAD_CurrentVersionRun_3ddb {
  strings:
    $key_3ddb = { 6e b4 [2] 4a ba [2] 61 96 [2] 4f b4 [2] 5b af [2] 54 b5 [2] 4a a8 [2] 48 a9 [2] 53 af [2] 4f a8 [2] 53 87 }

  condition:
    any of them
}