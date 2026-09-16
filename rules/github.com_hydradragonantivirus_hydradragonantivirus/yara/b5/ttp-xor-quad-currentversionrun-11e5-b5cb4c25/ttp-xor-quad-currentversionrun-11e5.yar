rule TTP_XOR_QUAD_CurrentVersionRun_11e5 {
  strings:
    $key_11e5 = { 42 8a [2] 66 84 [2] 4d a8 [2] 63 8a [2] 77 91 [2] 78 8b [2] 66 96 [2] 64 97 [2] 7f 91 [2] 63 96 [2] 7f b9 }

  condition:
    any of them
}