rule TTP_XOR_QUAD_CurrentVersionRun_2beb {
  strings:
    $key_2beb = { 78 84 [2] 5c 8a [2] 77 a6 [2] 59 84 [2] 4d 9f [2] 42 85 [2] 5c 98 [2] 5e 99 [2] 45 9f [2] 59 98 [2] 45 b7 }

  condition:
    any of them
}