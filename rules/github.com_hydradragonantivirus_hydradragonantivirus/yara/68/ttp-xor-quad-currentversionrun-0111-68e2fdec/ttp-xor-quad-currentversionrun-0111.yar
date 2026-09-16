rule TTP_XOR_QUAD_CurrentVersionRun_0111 {
  strings:
    $key_0111 = { 52 7e [2] 76 70 [2] 5d 5c [2] 73 7e [2] 67 65 [2] 68 7f [2] 76 62 [2] 74 63 [2] 6f 65 [2] 73 62 [2] 6f 4d }

  condition:
    any of them
}