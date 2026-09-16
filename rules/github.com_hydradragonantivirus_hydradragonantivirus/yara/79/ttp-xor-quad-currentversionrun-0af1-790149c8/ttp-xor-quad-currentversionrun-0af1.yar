rule TTP_XOR_QUAD_CurrentVersionRun_0af1 {
  strings:
    $key_0af1 = { 59 9e [2] 7d 90 [2] 56 bc [2] 78 9e [2] 6c 85 [2] 63 9f [2] 7d 82 [2] 7f 83 [2] 64 85 [2] 78 82 [2] 64 ad }

  condition:
    any of them
}