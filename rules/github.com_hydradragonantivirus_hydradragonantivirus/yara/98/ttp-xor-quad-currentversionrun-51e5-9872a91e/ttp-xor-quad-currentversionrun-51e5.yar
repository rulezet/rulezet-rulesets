rule TTP_XOR_QUAD_CurrentVersionRun_51e5 {
  strings:
    $key_51e5 = { 02 8a [2] 26 84 [2] 0d a8 [2] 23 8a [2] 37 91 [2] 38 8b [2] 26 96 [2] 24 97 [2] 3f 91 [2] 23 96 [2] 3f b9 }

  condition:
    any of them
}