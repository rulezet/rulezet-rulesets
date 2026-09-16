rule TTP_XOR_QUAD_CurrentVersionRun_09eb {
  strings:
    $key_09eb = { 5a 84 [2] 7e 8a [2] 55 a6 [2] 7b 84 [2] 6f 9f [2] 60 85 [2] 7e 98 [2] 7c 99 [2] 67 9f [2] 7b 98 [2] 67 b7 }

  condition:
    any of them
}