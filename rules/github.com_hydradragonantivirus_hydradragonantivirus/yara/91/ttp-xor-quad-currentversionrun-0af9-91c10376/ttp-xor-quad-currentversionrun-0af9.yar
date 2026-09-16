rule TTP_XOR_QUAD_CurrentVersionRun_0af9 {
  strings:
    $key_0af9 = { 59 96 [2] 7d 98 [2] 56 b4 [2] 78 96 [2] 6c 8d [2] 63 97 [2] 7d 8a [2] 7f 8b [2] 64 8d [2] 78 8a [2] 64 a5 }

  condition:
    any of them
}