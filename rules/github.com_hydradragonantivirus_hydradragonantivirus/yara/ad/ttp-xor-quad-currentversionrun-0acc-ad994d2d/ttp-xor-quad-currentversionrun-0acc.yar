rule TTP_XOR_QUAD_CurrentVersionRun_0acc {
  strings:
    $key_0acc = { 59 a3 [2] 7d ad [2] 56 81 [2] 78 a3 [2] 6c b8 [2] 63 a2 [2] 7d bf [2] 7f be [2] 64 b8 [2] 78 bf [2] 64 90 }

  condition:
    any of them
}