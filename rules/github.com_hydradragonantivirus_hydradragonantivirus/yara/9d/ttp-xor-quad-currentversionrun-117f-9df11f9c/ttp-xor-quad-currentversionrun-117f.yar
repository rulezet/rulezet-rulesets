rule TTP_XOR_QUAD_CurrentVersionRun_117f {
  strings:
    $key_117f = { 42 10 [2] 66 1e [2] 4d 32 [2] 63 10 [2] 77 0b [2] 78 11 [2] 66 0c [2] 64 0d [2] 7f 0b [2] 63 0c [2] 7f 23 }

  condition:
    any of them
}