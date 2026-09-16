rule TTP_XOR_QUAD_CurrentVersionRun_f0eb {
  strings:
    $key_f0eb = { a3 84 [2] 87 8a [2] ac a6 [2] 82 84 [2] 96 9f [2] 99 85 [2] 87 98 [2] 85 99 [2] 9e 9f [2] 82 98 [2] 9e b7 }

  condition:
    any of them
}