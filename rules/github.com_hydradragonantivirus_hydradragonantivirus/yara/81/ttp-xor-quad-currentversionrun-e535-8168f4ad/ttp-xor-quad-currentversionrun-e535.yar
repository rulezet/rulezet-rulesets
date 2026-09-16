rule TTP_XOR_QUAD_CurrentVersionRun_e535 {
  strings:
    $key_e535 = { b6 5a [2] 92 54 [2] b9 78 [2] 97 5a [2] 83 41 [2] 8c 5b [2] 92 46 [2] 90 47 [2] 8b 41 [2] 97 46 [2] 8b 69 }

  condition:
    any of them
}