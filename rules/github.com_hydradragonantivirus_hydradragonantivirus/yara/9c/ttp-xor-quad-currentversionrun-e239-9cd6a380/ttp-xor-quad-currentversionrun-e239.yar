rule TTP_XOR_QUAD_CurrentVersionRun_e239 {
  strings:
    $key_e239 = { b1 56 [2] 95 58 [2] be 74 [2] 90 56 [2] 84 4d [2] 8b 57 [2] 95 4a [2] 97 4b [2] 8c 4d [2] 90 4a [2] 8c 65 }

  condition:
    any of them
}