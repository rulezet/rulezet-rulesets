rule TTP_XOR_QUAD_CurrentVersionRun_3f7f {
  strings:
    $key_3f7f = { 6c 10 [2] 48 1e [2] 63 32 [2] 4d 10 [2] 59 0b [2] 56 11 [2] 48 0c [2] 4a 0d [2] 51 0b [2] 4d 0c [2] 51 23 }

  condition:
    any of them
}