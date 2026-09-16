rule TTP_XOR_QUAD_CurrentVersionRun_f1e5 {
  strings:
    $key_f1e5 = { a2 8a [2] 86 84 [2] ad a8 [2] 83 8a [2] 97 91 [2] 98 8b [2] 86 96 [2] 84 97 [2] 9f 91 [2] 83 96 [2] 9f b9 }

  condition:
    any of them
}