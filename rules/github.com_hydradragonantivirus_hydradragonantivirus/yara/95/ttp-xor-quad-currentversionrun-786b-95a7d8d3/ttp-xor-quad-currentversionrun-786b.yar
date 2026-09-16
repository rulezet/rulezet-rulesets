rule TTP_XOR_QUAD_CurrentVersionRun_786b {
  strings:
    $key_786b = { 2b 04 [2] 0f 0a [2] 24 26 [2] 0a 04 [2] 1e 1f [2] 11 05 [2] 0f 18 [2] 0d 19 [2] 16 1f [2] 0a 18 [2] 16 37 }

  condition:
    any of them
}