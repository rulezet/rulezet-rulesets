rule TTP_XOR_QUAD_CurrentVersionRun_e217 {
  strings:
    $key_e217 = { b1 78 [2] 95 76 [2] be 5a [2] 90 78 [2] 84 63 [2] 8b 79 [2] 95 64 [2] 97 65 [2] 8c 63 [2] 90 64 [2] 8c 4b }

  condition:
    any of them
}