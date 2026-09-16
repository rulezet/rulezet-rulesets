rule TTP_XOR_QUAD_CurrentVersionRun_0dff {
  strings:
    $key_0dff = { 5e 90 [2] 7a 9e [2] 51 b2 [2] 7f 90 [2] 6b 8b [2] 64 91 [2] 7a 8c [2] 78 8d [2] 63 8b [2] 7f 8c [2] 63 a3 }

  condition:
    any of them
}