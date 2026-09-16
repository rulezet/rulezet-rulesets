rule TTP_XOR_QUAD_CurrentVersionRun_e26b {
  strings:
    $key_e26b = { b1 04 [2] 95 0a [2] be 26 [2] 90 04 [2] 84 1f [2] 8b 05 [2] 95 18 [2] 97 19 [2] 8c 1f [2] 90 18 [2] 8c 37 }

  condition:
    any of them
}