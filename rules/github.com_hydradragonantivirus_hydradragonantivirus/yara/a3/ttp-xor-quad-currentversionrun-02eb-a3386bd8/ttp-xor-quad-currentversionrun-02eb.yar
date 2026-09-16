rule TTP_XOR_QUAD_CurrentVersionRun_02eb {
  strings:
    $key_02eb = { 51 84 [2] 75 8a [2] 5e a6 [2] 70 84 [2] 64 9f [2] 6b 85 [2] 75 98 [2] 77 99 [2] 6c 9f [2] 70 98 [2] 6c b7 }

  condition:
    any of them
}