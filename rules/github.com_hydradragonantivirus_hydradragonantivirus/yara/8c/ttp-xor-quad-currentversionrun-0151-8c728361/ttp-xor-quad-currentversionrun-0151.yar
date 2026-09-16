rule TTP_XOR_QUAD_CurrentVersionRun_0151 {
  strings:
    $key_0151 = { 52 3e [2] 76 30 [2] 5d 1c [2] 73 3e [2] 67 25 [2] 68 3f [2] 76 22 [2] 74 23 [2] 6f 25 [2] 73 22 [2] 6f 0d }

  condition:
    any of them
}