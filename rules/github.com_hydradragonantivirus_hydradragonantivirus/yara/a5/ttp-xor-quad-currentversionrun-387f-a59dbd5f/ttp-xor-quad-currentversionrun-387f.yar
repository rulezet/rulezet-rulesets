rule TTP_XOR_QUAD_CurrentVersionRun_387f {
  strings:
    $key_387f = { 6b 10 [2] 4f 1e [2] 64 32 [2] 4a 10 [2] 5e 0b [2] 51 11 [2] 4f 0c [2] 4d 0d [2] 56 0b [2] 4a 0c [2] 56 23 }

  condition:
    any of them
}