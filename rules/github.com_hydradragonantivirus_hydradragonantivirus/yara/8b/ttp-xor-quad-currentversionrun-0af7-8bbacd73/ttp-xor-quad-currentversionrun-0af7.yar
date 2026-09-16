rule TTP_XOR_QUAD_CurrentVersionRun_0af7 {
  strings:
    $key_0af7 = { 59 98 [2] 7d 96 [2] 56 ba [2] 78 98 [2] 6c 83 [2] 63 99 [2] 7d 84 [2] 7f 85 [2] 64 83 [2] 78 84 [2] 64 ab }

  condition:
    any of them
}