rule TTP_XOR_QUAD_CurrentVersionRun_014a {
  strings:
    $key_014a = { 52 25 [2] 76 2b [2] 5d 07 [2] 73 25 [2] 67 3e [2] 68 24 [2] 76 39 [2] 74 38 [2] 6f 3e [2] 73 39 [2] 6f 16 }

  condition:
    any of them
}