rule TTP_XOR_QUAD_CurrentVersionRun_0121 {
  strings:
    $key_0121 = { 52 4e [2] 76 40 [2] 5d 6c [2] 73 4e [2] 67 55 [2] 68 4f [2] 76 52 [2] 74 53 [2] 6f 55 [2] 73 52 [2] 6f 7d }

  condition:
    any of them
}