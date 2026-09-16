rule TTP_XOR_QUAD_CurrentVersionRun_11eb {
  strings:
    $key_11eb = { 42 84 [2] 66 8a [2] 4d a6 [2] 63 84 [2] 77 9f [2] 78 85 [2] 66 98 [2] 64 99 [2] 7f 9f [2] 63 98 [2] 7f b7 }

  condition:
    any of them
}