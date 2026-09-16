rule TTP_XOR_QUAD_CurrentVersionRun_067b {
  strings:
    $key_067b = { 55 14 [2] 71 1a [2] 5a 36 [2] 74 14 [2] 60 0f [2] 6f 15 [2] 71 08 [2] 73 09 [2] 68 0f [2] 74 08 [2] 68 27 }

  condition:
    any of them
}