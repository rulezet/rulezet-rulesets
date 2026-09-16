rule TTP_XOR_QUAD_CurrentVersionRun_15e5 {
  strings:
    $key_15e5 = { 46 8a [2] 62 84 [2] 49 a8 [2] 67 8a [2] 73 91 [2] 7c 8b [2] 62 96 [2] 60 97 [2] 7b 91 [2] 67 96 [2] 7b b9 }

  condition:
    any of them
}