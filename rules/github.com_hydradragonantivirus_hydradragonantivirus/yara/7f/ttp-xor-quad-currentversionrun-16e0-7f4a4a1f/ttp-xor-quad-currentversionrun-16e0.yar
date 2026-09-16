rule TTP_XOR_QUAD_CurrentVersionRun_16e0 {
  strings:
    $key_16e0 = { 45 8f [2] 61 81 [2] 4a ad [2] 64 8f [2] 70 94 [2] 7f 8e [2] 61 93 [2] 63 92 [2] 78 94 [2] 64 93 [2] 78 bc }

  condition:
    any of them
}