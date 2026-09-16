rule TTP_XOR_QUAD_CurrentVersionRun_0421 {
  strings:
    $key_0421 = { 57 4e [2] 73 40 [2] 58 6c [2] 76 4e [2] 62 55 [2] 6d 4f [2] 73 52 [2] 71 53 [2] 6a 55 [2] 76 52 [2] 6a 7d }

  condition:
    any of them
}