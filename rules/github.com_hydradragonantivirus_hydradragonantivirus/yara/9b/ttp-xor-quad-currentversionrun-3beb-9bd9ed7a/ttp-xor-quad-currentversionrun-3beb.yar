rule TTP_XOR_QUAD_CurrentVersionRun_3beb {
  strings:
    $key_3beb = { 68 84 [2] 4c 8a [2] 67 a6 [2] 49 84 [2] 5d 9f [2] 52 85 [2] 4c 98 [2] 4e 99 [2] 55 9f [2] 49 98 [2] 55 b7 }

  condition:
    any of them
}