rule TTP_XOR_QUAD_CurrentVersionRun_0310 {
  strings:
    $key_0310 = { 50 7f [2] 74 71 [2] 5f 5d [2] 71 7f [2] 65 64 [2] 6a 7e [2] 74 63 [2] 76 62 [2] 6d 64 [2] 71 63 [2] 6d 4c }

  condition:
    any of them
}