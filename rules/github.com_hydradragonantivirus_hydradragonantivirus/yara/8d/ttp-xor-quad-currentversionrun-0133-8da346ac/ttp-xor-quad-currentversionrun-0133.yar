rule TTP_XOR_QUAD_CurrentVersionRun_0133 {
  strings:
    $key_0133 = { 52 5c [2] 76 52 [2] 5d 7e [2] 73 5c [2] 67 47 [2] 68 5d [2] 76 40 [2] 74 41 [2] 6f 47 [2] 73 40 [2] 6f 6f }

  condition:
    any of them
}