rule TTP_XOR_QUAD_CurrentVersionRun_0311 {
  strings:
    $key_0311 = { 50 7e [2] 74 70 [2] 5f 5c [2] 71 7e [2] 65 65 [2] 6a 7f [2] 74 62 [2] 76 63 [2] 6d 65 [2] 71 62 [2] 6d 4d }

  condition:
    any of them
}