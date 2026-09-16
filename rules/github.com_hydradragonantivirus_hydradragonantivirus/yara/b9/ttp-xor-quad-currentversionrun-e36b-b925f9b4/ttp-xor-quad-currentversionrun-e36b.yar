rule TTP_XOR_QUAD_CurrentVersionRun_e36b {
  strings:
    $key_e36b = { b0 04 [2] 94 0a [2] bf 26 [2] 91 04 [2] 85 1f [2] 8a 05 [2] 94 18 [2] 96 19 [2] 8d 1f [2] 91 18 [2] 8d 37 }

  condition:
    any of them
}