rule TTP_XOR_QUAD_CurrentVersionRun_0d2a {
  strings:
    $key_0d2a = { 5e 45 [2] 7a 4b [2] 51 67 [2] 7f 45 [2] 6b 5e [2] 64 44 [2] 7a 59 [2] 78 58 [2] 63 5e [2] 7f 59 [2] 63 76 }

  condition:
    any of them
}