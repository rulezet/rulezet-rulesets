rule TTP_XOR_QUAD_CurrentVersionRun_e21b {
  strings:
    $key_e21b = { b1 74 [2] 95 7a [2] be 56 [2] 90 74 [2] 84 6f [2] 8b 75 [2] 95 68 [2] 97 69 [2] 8c 6f [2] 90 68 [2] 8c 47 }

  condition:
    any of them
}