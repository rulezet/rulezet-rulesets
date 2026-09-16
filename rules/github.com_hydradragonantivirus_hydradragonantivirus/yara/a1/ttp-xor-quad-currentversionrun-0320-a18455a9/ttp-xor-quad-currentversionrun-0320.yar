rule TTP_XOR_QUAD_CurrentVersionRun_0320 {
  strings:
    $key_0320 = { 50 4f [2] 74 41 [2] 5f 6d [2] 71 4f [2] 65 54 [2] 6a 4e [2] 74 53 [2] 76 52 [2] 6d 54 [2] 71 53 [2] 6d 7c }

  condition:
    any of them
}