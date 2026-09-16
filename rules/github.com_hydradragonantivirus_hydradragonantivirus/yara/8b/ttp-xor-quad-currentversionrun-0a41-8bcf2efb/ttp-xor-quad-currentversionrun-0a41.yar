rule TTP_XOR_QUAD_CurrentVersionRun_0a41 {
  strings:
    $key_0a41 = { 59 2e [2] 7d 20 [2] 56 0c [2] 78 2e [2] 6c 35 [2] 63 2f [2] 7d 32 [2] 7f 33 [2] 64 35 [2] 78 32 [2] 64 1d }

  condition:
    any of them
}