rule TTP_XOR_QUAD_CurrentVersionRun_0ffc {
  strings:
    $key_0ffc = { 5c 93 [2] 78 9d [2] 53 b1 [2] 7d 93 [2] 69 88 [2] 66 92 [2] 78 8f [2] 7a 8e [2] 61 88 [2] 7d 8f [2] 61 a0 }

  condition:
    any of them
}