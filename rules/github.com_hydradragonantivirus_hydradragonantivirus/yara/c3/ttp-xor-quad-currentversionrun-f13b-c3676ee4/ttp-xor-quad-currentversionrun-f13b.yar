rule TTP_XOR_QUAD_CurrentVersionRun_f13b {
  strings:
    $key_f13b = { a2 54 [2] 86 5a [2] ad 76 [2] 83 54 [2] 97 4f [2] 98 55 [2] 86 48 [2] 84 49 [2] 9f 4f [2] 83 48 [2] 9f 67 }

  condition:
    any of them
}