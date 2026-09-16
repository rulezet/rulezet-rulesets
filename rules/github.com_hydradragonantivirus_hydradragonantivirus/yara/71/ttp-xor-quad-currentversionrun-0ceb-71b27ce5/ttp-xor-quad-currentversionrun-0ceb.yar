rule TTP_XOR_QUAD_CurrentVersionRun_0ceb {
  strings:
    $key_0ceb = { 5f 84 [2] 7b 8a [2] 50 a6 [2] 7e 84 [2] 6a 9f [2] 65 85 [2] 7b 98 [2] 79 99 [2] 62 9f [2] 7e 98 [2] 62 b7 }

  condition:
    any of them
}