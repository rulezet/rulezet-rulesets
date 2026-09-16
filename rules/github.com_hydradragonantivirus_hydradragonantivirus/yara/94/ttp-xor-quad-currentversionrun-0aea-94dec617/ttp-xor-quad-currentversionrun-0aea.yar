rule TTP_XOR_QUAD_CurrentVersionRun_0aea {
  strings:
    $key_0aea = { 59 85 [2] 7d 8b [2] 56 a7 [2] 78 85 [2] 6c 9e [2] 63 84 [2] 7d 99 [2] 7f 98 [2] 64 9e [2] 78 99 [2] 64 b6 }

  condition:
    any of them
}