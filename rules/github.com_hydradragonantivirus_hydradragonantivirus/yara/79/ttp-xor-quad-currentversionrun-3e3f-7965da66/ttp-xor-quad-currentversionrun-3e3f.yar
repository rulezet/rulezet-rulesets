rule TTP_XOR_QUAD_CurrentVersionRun_3e3f {
  strings:
    $key_3e3f = { 6d 50 [2] 49 5e [2] 62 72 [2] 4c 50 [2] 58 4b [2] 57 51 [2] 49 4c [2] 4b 4d [2] 50 4b [2] 4c 4c [2] 50 63 }

  condition:
    any of them
}