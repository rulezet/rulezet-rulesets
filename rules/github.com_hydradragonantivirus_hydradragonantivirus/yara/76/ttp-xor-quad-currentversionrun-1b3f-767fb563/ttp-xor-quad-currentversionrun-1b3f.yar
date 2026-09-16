rule TTP_XOR_QUAD_CurrentVersionRun_1b3f {
  strings:
    $key_1b3f = { 48 50 [2] 6c 5e [2] 47 72 [2] 69 50 [2] 7d 4b [2] 72 51 [2] 6c 4c [2] 6e 4d [2] 75 4b [2] 69 4c [2] 75 63 }

  condition:
    any of them
}