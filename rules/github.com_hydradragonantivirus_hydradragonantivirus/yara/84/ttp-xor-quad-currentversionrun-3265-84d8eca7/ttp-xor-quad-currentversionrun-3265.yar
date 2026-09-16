rule TTP_XOR_QUAD_CurrentVersionRun_3265 {
  strings:
    $key_3265 = { 61 0a [2] 45 04 [2] 6e 28 [2] 40 0a [2] 54 11 [2] 5b 0b [2] 45 16 [2] 47 17 [2] 5c 11 [2] 40 16 [2] 5c 39 }

  condition:
    any of them
}