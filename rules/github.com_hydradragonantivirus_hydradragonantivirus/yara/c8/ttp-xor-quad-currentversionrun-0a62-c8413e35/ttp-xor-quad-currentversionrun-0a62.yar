rule TTP_XOR_QUAD_CurrentVersionRun_0a62 {
  strings:
    $key_0a62 = { 59 0d [2] 7d 03 [2] 56 2f [2] 78 0d [2] 6c 16 [2] 63 0c [2] 7d 11 [2] 7f 10 [2] 64 16 [2] 78 11 [2] 64 3e }

  condition:
    any of them
}