rule TTP_XOR_QUAD_CurrentVersionRun_e238 {
  strings:
    $key_e238 = { b1 57 [2] 95 59 [2] be 75 [2] 90 57 [2] 84 4c [2] 8b 56 [2] 95 4b [2] 97 4a [2] 8c 4c [2] 90 4b [2] 8c 64 }

  condition:
    any of them
}