rule TTP_XOR_QUAD_CurrentVersionRun_0a5f {
  strings:
    $key_0a5f = { 59 30 [2] 7d 3e [2] 56 12 [2] 78 30 [2] 6c 2b [2] 63 31 [2] 7d 2c [2] 7f 2d [2] 64 2b [2] 78 2c [2] 64 03 }

  condition:
    any of them
}