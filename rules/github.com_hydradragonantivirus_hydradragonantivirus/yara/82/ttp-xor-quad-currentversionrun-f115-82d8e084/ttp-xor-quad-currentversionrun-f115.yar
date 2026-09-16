rule TTP_XOR_QUAD_CurrentVersionRun_f115 {
  strings:
    $key_f115 = { a2 7a [2] 86 74 [2] ad 58 [2] 83 7a [2] 97 61 [2] 98 7b [2] 86 66 [2] 84 67 [2] 9f 61 [2] 83 66 [2] 9f 49 }

  condition:
    any of them
}