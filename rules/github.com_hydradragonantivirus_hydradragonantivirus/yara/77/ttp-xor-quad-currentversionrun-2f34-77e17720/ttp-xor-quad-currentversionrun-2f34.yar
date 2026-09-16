rule TTP_XOR_QUAD_CurrentVersionRun_2f34 {
  strings:
    $key_2f34 = { 7c 5b [2] 58 55 [2] 73 79 [2] 5d 5b [2] 49 40 [2] 46 5a [2] 58 47 [2] 5a 46 [2] 41 40 [2] 5d 47 [2] 41 68 }

  condition:
    any of them
}