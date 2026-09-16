rule TTP_XOR_QUAD_CurrentVersionRun_e274 {
  strings:
    $key_e274 = { b1 1b [2] 95 15 [2] be 39 [2] 90 1b [2] 84 00 [2] 8b 1a [2] 95 07 [2] 97 06 [2] 8c 00 [2] 90 07 [2] 8c 28 }

  condition:
    any of them
}