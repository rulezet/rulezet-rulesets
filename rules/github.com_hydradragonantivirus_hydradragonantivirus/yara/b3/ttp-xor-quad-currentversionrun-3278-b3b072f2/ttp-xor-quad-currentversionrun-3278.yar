rule TTP_XOR_QUAD_CurrentVersionRun_3278 {
  strings:
    $key_3278 = { 61 17 [2] 45 19 [2] 6e 35 [2] 40 17 [2] 54 0c [2] 5b 16 [2] 45 0b [2] 47 0a [2] 5c 0c [2] 40 0b [2] 5c 24 }

  condition:
    any of them
}