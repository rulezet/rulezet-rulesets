rule TTP_XOR_QUAD_CurrentVersionRun_30e5 {
  strings:
    $key_30e5 = { 63 8a [2] 47 84 [2] 6c a8 [2] 42 8a [2] 56 91 [2] 59 8b [2] 47 96 [2] 45 97 [2] 5e 91 [2] 42 96 [2] 5e b9 }

  condition:
    any of them
}