rule TTP_XOR_QUAD_CurrentVersionRun_eacc {
  strings:
    $key_eacc = { b9 a3 [2] 9d ad [2] b6 81 [2] 98 a3 [2] 8c b8 [2] 83 a2 [2] 9d bf [2] 9f be [2] 84 b8 [2] 98 bf [2] 84 90 }

  condition:
    any of them
}