rule TTP_XOR_QUAD_CurrentVersionRun_2ee5 {
  strings:
    $key_2ee5 = { 7d 8a [2] 59 84 [2] 72 a8 [2] 5c 8a [2] 48 91 [2] 47 8b [2] 59 96 [2] 5b 97 [2] 40 91 [2] 5c 96 [2] 40 b9 }

  condition:
    any of them
}