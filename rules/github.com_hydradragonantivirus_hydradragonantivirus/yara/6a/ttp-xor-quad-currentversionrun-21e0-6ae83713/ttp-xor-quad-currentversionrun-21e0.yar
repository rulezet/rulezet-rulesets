rule TTP_XOR_QUAD_CurrentVersionRun_21e0 {
  strings:
    $key_21e0 = { 72 8f [2] 56 81 [2] 7d ad [2] 53 8f [2] 47 94 [2] 48 8e [2] 56 93 [2] 54 92 [2] 4f 94 [2] 53 93 [2] 4f bc }

  condition:
    any of them
}