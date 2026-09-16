rule TTP_XOR_QUAD_CurrentVersionRun_0d0a {
  strings:
    $key_0d0a = { 5e 65 [2] 7a 6b [2] 51 47 [2] 7f 65 [2] 6b 7e [2] 64 64 [2] 7a 79 [2] 78 78 [2] 63 7e [2] 7f 79 [2] 63 56 }

  condition:
    any of them
}