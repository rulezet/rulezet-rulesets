rule TTP_XOR_QUAD_CurrentVersionRun_3ceb {
  strings:
    $key_3ceb = { 6f 84 [2] 4b 8a [2] 60 a6 [2] 4e 84 [2] 5a 9f [2] 55 85 [2] 4b 98 [2] 49 99 [2] 52 9f [2] 4e 98 [2] 52 b7 }

  condition:
    any of them
}