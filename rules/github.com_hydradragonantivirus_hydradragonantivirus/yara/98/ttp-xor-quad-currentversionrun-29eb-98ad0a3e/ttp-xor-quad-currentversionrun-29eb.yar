rule TTP_XOR_QUAD_CurrentVersionRun_29eb {
  strings:
    $key_29eb = { 7a 84 [2] 5e 8a [2] 75 a6 [2] 5b 84 [2] 4f 9f [2] 40 85 [2] 5e 98 [2] 5c 99 [2] 47 9f [2] 5b 98 [2] 47 b7 }

  condition:
    any of them
}