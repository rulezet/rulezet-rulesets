rule TTP_XOR_QUAD_CurrentVersionRun_39eb {
  strings:
    $key_39eb = { 6a 84 [2] 4e 8a [2] 65 a6 [2] 4b 84 [2] 5f 9f [2] 50 85 [2] 4e 98 [2] 4c 99 [2] 57 9f [2] 4b 98 [2] 57 b7 }

  condition:
    any of them
}