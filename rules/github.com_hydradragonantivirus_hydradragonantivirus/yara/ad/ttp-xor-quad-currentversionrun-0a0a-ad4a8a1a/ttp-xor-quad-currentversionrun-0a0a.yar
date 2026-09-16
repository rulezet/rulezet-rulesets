rule TTP_XOR_QUAD_CurrentVersionRun_0a0a {
  strings:
    $key_0a0a = { 59 65 [2] 7d 6b [2] 56 47 [2] 78 65 [2] 6c 7e [2] 63 64 [2] 7d 79 [2] 7f 78 [2] 64 7e [2] 78 79 [2] 64 56 }

  condition:
    any of them
}