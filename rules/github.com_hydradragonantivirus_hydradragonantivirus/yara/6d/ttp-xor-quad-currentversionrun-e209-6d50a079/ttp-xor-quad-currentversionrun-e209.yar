rule TTP_XOR_QUAD_CurrentVersionRun_e209 {
  strings:
    $key_e209 = { b1 66 [2] 95 68 [2] be 44 [2] 90 66 [2] 84 7d [2] 8b 67 [2] 95 7a [2] 97 7b [2] 8c 7d [2] 90 7a [2] 8c 55 }

  condition:
    any of them
}