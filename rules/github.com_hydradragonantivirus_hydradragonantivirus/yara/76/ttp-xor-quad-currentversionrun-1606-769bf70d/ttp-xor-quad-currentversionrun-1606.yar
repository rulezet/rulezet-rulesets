rule TTP_XOR_QUAD_CurrentVersionRun_1606 {
  strings:
    $key_1606 = { 45 69 [2] 61 67 [2] 4a 4b [2] 64 69 [2] 70 72 [2] 7f 68 [2] 61 75 [2] 63 74 [2] 78 72 [2] 64 75 [2] 78 5a }

  condition:
    any of them
}