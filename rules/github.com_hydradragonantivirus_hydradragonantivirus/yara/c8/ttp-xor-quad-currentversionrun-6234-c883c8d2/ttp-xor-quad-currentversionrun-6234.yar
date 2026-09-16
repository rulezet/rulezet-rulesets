rule TTP_XOR_QUAD_CurrentVersionRun_6234 {
  strings:
    $key_6234 = { 31 5b [2] 15 55 [2] 3e 79 [2] 10 5b [2] 04 40 [2] 0b 5a [2] 15 47 [2] 17 46 [2] 0c 40 [2] 10 47 [2] 0c 68 }

  condition:
    any of them
}