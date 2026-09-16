rule TTP_XOR_QUAD_CurrentVersionRun_2ef9 {
  strings:
    $key_2ef9 = { 7d 96 [2] 59 98 [2] 72 b4 [2] 5c 96 [2] 48 8d [2] 47 97 [2] 59 8a [2] 5b 8b [2] 40 8d [2] 5c 8a [2] 40 a5 }

  condition:
    any of them
}