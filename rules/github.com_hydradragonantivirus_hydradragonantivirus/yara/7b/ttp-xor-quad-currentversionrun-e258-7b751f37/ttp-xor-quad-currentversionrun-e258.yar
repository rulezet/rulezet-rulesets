rule TTP_XOR_QUAD_CurrentVersionRun_e258 {
  strings:
    $key_e258 = { b1 37 [2] 95 39 [2] be 15 [2] 90 37 [2] 84 2c [2] 8b 36 [2] 95 2b [2] 97 2a [2] 8c 2c [2] 90 2b [2] 8c 04 }

  condition:
    any of them
}