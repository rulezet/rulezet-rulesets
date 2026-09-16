rule TTP_XOR_QUAD_CurrentVersionRun_0de0 {
  strings:
    $key_0de0 = { 5e 8f [2] 7a 81 [2] 51 ad [2] 7f 8f [2] 6b 94 [2] 64 8e [2] 7a 93 [2] 78 92 [2] 63 94 [2] 7f 93 [2] 63 bc }

  condition:
    any of them
}