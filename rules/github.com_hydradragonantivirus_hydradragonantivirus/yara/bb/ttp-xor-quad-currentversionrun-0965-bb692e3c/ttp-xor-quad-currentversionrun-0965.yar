rule TTP_XOR_QUAD_CurrentVersionRun_0965 {
  strings:
    $key_0965 = { 5a 0a [2] 7e 04 [2] 55 28 [2] 7b 0a [2] 6f 11 [2] 60 0b [2] 7e 16 [2] 7c 17 [2] 67 11 [2] 7b 16 [2] 67 39 }

  condition:
    any of them
}