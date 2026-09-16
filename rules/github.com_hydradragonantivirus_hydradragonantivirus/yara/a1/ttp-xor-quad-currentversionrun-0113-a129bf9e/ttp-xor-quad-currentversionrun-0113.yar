rule TTP_XOR_QUAD_CurrentVersionRun_0113 {
  strings:
    $key_0113 = { 52 7c [2] 76 72 [2] 5d 5e [2] 73 7c [2] 67 67 [2] 68 7d [2] 76 60 [2] 74 61 [2] 6f 67 [2] 73 60 [2] 6f 4f }

  condition:
    any of them
}