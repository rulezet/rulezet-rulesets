rule TTP_XOR_QUAD_CurrentVersionRun_0dea {
  strings:
    $key_0dea = { 5e 85 [2] 7a 8b [2] 51 a7 [2] 7f 85 [2] 6b 9e [2] 64 84 [2] 7a 99 [2] 78 98 [2] 63 9e [2] 7f 99 [2] 63 b6 }

  condition:
    any of them
}