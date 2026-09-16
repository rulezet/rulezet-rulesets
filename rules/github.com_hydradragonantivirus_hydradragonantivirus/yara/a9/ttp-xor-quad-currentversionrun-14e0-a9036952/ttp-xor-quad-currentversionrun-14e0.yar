rule TTP_XOR_QUAD_CurrentVersionRun_14e0 {
  strings:
    $key_14e0 = { 47 8f [2] 63 81 [2] 48 ad [2] 66 8f [2] 72 94 [2] 7d 8e [2] 63 93 [2] 61 92 [2] 7a 94 [2] 66 93 [2] 7a bc }

  condition:
    any of them
}