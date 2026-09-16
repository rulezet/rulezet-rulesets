rule TTP_XOR_QUAD_CurrentVersionRun_0ae0 {
  strings:
    $key_0ae0 = { 59 8f [2] 7d 81 [2] 56 ad [2] 78 8f [2] 6c 94 [2] 63 8e [2] 7d 93 [2] 7f 92 [2] 64 94 [2] 78 93 [2] 64 bc }

  condition:
    any of them
}