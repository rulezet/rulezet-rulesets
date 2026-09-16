rule TTP_XOR_QUAD_CurrentVersionRun_e36a {
  strings:
    $key_e36a = { b0 05 [2] 94 0b [2] bf 27 [2] 91 05 [2] 85 1e [2] 8a 04 [2] 94 19 [2] 96 18 [2] 8d 1e [2] 91 19 [2] 8d 36 }

  condition:
    any of them
}