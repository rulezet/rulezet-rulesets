rule TTP_XOR_QUAD_CurrentVersionRun_0b3f {
  strings:
    $key_0b3f = { 58 50 [2] 7c 5e [2] 57 72 [2] 79 50 [2] 6d 4b [2] 62 51 [2] 7c 4c [2] 7e 4d [2] 65 4b [2] 79 4c [2] 65 63 }

  condition:
    any of them
}