rule TTP_XOR_QUAD_CurrentVersionRun_0a7c {
  strings:
    $key_0a7c = { 59 13 [2] 7d 1d [2] 56 31 [2] 78 13 [2] 6c 08 [2] 63 12 [2] 7d 0f [2] 7f 0e [2] 64 08 [2] 78 0f [2] 64 20 }

  condition:
    any of them
}