rule TTP_XOR_QUAD_CurrentVersionRun_6c0a {
  strings:
    $key_6c0a = { 3f 65 [2] 1b 6b [2] 30 47 [2] 1e 65 [2] 0a 7e [2] 05 64 [2] 1b 79 [2] 19 78 [2] 02 7e [2] 1e 79 [2] 02 56 }

  condition:
    any of them
}