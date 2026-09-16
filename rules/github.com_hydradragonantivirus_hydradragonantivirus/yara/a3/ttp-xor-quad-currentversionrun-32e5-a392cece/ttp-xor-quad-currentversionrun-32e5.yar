rule TTP_XOR_QUAD_CurrentVersionRun_32e5 {
  strings:
    $key_32e5 = { 61 8a [2] 45 84 [2] 6e a8 [2] 40 8a [2] 54 91 [2] 5b 8b [2] 45 96 [2] 47 97 [2] 5c 91 [2] 40 96 [2] 5c b9 }

  condition:
    any of them
}