rule TTP_XOR_QUAD_CurrentVersionRun_6aff {
  strings:
    $key_6aff = { 39 90 [2] 1d 9e [2] 36 b2 [2] 18 90 [2] 0c 8b [2] 03 91 [2] 1d 8c [2] 1f 8d [2] 04 8b [2] 18 8c [2] 04 a3 }

  condition:
    any of them
}