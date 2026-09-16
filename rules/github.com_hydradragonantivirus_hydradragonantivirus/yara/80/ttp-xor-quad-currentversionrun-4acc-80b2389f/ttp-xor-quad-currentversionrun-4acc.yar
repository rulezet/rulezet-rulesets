rule TTP_XOR_QUAD_CurrentVersionRun_4acc {
  strings:
    $key_4acc = { 19 a3 [2] 3d ad [2] 16 81 [2] 38 a3 [2] 2c b8 [2] 23 a2 [2] 3d bf [2] 3f be [2] 24 b8 [2] 38 bf [2] 24 90 }

  condition:
    any of them
}