rule TTP_XOR_QUAD_CurrentVersionRun_6434 {
  strings:
    $key_6434 = { 37 5b [2] 13 55 [2] 38 79 [2] 16 5b [2] 02 40 [2] 0d 5a [2] 13 47 [2] 11 46 [2] 0a 40 [2] 16 47 [2] 0a 68 }

  condition:
    any of them
}