rule TTP_XOR_QUAD_CurrentVersionRun_19e5 {
  strings:
    $key_19e5 = { 4a 8a [2] 6e 84 [2] 45 a8 [2] 6b 8a [2] 7f 91 [2] 70 8b [2] 6e 96 [2] 6c 97 [2] 77 91 [2] 6b 96 [2] 77 b9 }

  condition:
    any of them
}