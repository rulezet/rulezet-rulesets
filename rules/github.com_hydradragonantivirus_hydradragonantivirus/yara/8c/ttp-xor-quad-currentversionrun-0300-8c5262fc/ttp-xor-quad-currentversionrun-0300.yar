rule TTP_XOR_QUAD_CurrentVersionRun_0300 {
  strings:
    $key_0300 = { 50 6f [2] 74 61 [2] 5f 4d [2] 71 6f [2] 65 74 [2] 6a 6e [2] 74 73 [2] 76 72 [2] 6d 74 [2] 71 73 [2] 6d 5c }

  condition:
    any of them
}