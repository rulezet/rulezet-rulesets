rule TTP_XOR_QUAD_CurrentVersionRun_016a {
  strings:
    $key_016a = { 52 05 [2] 76 0b [2] 5d 27 [2] 73 05 [2] 67 1e [2] 68 04 [2] 76 19 [2] 74 18 [2] 6f 1e [2] 73 19 [2] 6f 36 }

  condition:
    any of them
}