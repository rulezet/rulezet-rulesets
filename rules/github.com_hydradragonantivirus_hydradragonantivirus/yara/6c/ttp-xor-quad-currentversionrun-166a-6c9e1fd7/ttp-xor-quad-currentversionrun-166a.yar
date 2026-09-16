rule TTP_XOR_QUAD_CurrentVersionRun_166a {
  strings:
    $key_166a = { 45 05 [2] 61 0b [2] 4a 27 [2] 64 05 [2] 70 1e [2] 7f 04 [2] 61 19 [2] 63 18 [2] 78 1e [2] 64 19 [2] 78 36 }

  condition:
    any of them
}