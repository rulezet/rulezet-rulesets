rule TTP_XOR_QUAD_CurrentVersionRun_2a3f {
  strings:
    $key_2a3f = { 79 50 [2] 5d 5e [2] 76 72 [2] 58 50 [2] 4c 4b [2] 43 51 [2] 5d 4c [2] 5f 4d [2] 44 4b [2] 58 4c [2] 44 63 }

  condition:
    any of them
}