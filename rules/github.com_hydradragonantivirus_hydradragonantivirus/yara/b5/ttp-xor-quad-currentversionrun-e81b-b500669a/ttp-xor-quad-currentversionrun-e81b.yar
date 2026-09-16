rule TTP_XOR_QUAD_CurrentVersionRun_e81b {
  strings:
    $key_e81b = { bb 74 [2] 9f 7a [2] b4 56 [2] 9a 74 [2] 8e 6f [2] 81 75 [2] 9f 68 [2] 9d 69 [2] 86 6f [2] 9a 68 [2] 86 47 }

  condition:
    any of them
}