rule TTP_XOR_QUAD_CurrentVersionRun_6acc {
  strings:
    $key_6acc = { 39 a3 [2] 1d ad [2] 36 81 [2] 18 a3 [2] 0c b8 [2] 03 a2 [2] 1d bf [2] 1f be [2] 04 b8 [2] 18 bf [2] 04 90 }

  condition:
    any of them
}