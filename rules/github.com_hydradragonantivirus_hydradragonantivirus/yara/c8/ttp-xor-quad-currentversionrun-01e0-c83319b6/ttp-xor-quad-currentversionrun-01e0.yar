rule TTP_XOR_QUAD_CurrentVersionRun_01e0 {
  strings:
    $key_01e0 = { 52 8f [2] 76 81 [2] 5d ad [2] 73 8f [2] 67 94 [2] 68 8e [2] 76 93 [2] 74 92 [2] 6f 94 [2] 73 93 [2] 6f bc }

  condition:
    any of them
}