rule TTP_XOR_QUAD_CurrentVersionRun_e235 {
  strings:
    $key_e235 = { b1 5a [2] 95 54 [2] be 78 [2] 90 5a [2] 84 41 [2] 8b 5b [2] 95 46 [2] 97 47 [2] 8c 41 [2] 90 46 [2] 8c 69 }

  condition:
    any of them
}