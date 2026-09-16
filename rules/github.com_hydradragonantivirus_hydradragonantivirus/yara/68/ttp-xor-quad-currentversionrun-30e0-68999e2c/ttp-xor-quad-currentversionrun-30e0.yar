rule TTP_XOR_QUAD_CurrentVersionRun_30e0 {
  strings:
    $key_30e0 = { 63 8f [2] 47 81 [2] 6c ad [2] 42 8f [2] 56 94 [2] 59 8e [2] 47 93 [2] 45 92 [2] 5e 94 [2] 42 93 [2] 5e bc }

  condition:
    any of them
}