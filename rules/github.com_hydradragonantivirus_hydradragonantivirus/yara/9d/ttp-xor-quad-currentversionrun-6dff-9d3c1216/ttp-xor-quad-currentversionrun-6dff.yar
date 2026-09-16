rule TTP_XOR_QUAD_CurrentVersionRun_6dff {
  strings:
    $key_6dff = { 3e 90 [2] 1a 9e [2] 31 b2 [2] 1f 90 [2] 0b 8b [2] 04 91 [2] 1a 8c [2] 18 8d [2] 03 8b [2] 1f 8c [2] 03 a3 }

  condition:
    any of them
}