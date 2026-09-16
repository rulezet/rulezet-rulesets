rule TTP_XOR_QUAD_CurrentVersionRun_785f {
  strings:
    $key_785f = { 2b 30 [2] 0f 3e [2] 24 12 [2] 0a 30 [2] 1e 2b [2] 11 31 [2] 0f 2c [2] 0d 2d [2] 16 2b [2] 0a 2c [2] 16 03 }

  condition:
    any of them
}