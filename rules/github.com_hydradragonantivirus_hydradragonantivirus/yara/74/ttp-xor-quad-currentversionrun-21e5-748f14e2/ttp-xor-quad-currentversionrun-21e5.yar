rule TTP_XOR_QUAD_CurrentVersionRun_21e5 {
  strings:
    $key_21e5 = { 72 8a [2] 56 84 [2] 7d a8 [2] 53 8a [2] 47 91 [2] 48 8b [2] 56 96 [2] 54 97 [2] 4f 91 [2] 53 96 [2] 4f b9 }

  condition:
    any of them
}