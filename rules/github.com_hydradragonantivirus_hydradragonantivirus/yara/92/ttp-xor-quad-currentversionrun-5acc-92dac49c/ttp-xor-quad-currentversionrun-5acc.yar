rule TTP_XOR_QUAD_CurrentVersionRun_5acc {
  strings:
    $key_5acc = { 09 a3 [2] 2d ad [2] 06 81 [2] 28 a3 [2] 3c b8 [2] 33 a2 [2] 2d bf [2] 2f be [2] 34 b8 [2] 28 bf [2] 34 90 }

  condition:
    any of them
}