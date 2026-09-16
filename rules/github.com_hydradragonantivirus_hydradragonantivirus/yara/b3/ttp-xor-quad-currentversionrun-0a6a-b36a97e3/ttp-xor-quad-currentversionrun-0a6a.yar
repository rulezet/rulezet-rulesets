rule TTP_XOR_QUAD_CurrentVersionRun_0a6a {
  strings:
    $key_0a6a = { 59 05 [2] 7d 0b [2] 56 27 [2] 78 05 [2] 6c 1e [2] 63 04 [2] 7d 19 [2] 7f 18 [2] 64 1e [2] 78 19 [2] 64 36 }

  condition:
    any of them
}