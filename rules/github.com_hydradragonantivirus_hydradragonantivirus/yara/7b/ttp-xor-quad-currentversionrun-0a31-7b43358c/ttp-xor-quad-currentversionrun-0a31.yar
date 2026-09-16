rule TTP_XOR_QUAD_CurrentVersionRun_0a31 {
  strings:
    $key_0a31 = { 59 5e [2] 7d 50 [2] 56 7c [2] 78 5e [2] 6c 45 [2] 63 5f [2] 7d 42 [2] 7f 43 [2] 64 45 [2] 78 42 [2] 64 6d }

  condition:
    any of them
}