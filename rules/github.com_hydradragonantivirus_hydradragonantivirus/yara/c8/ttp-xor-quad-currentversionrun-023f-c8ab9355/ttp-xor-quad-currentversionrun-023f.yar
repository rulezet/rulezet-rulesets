rule TTP_XOR_QUAD_CurrentVersionRun_023f {
  strings:
    $key_023f = { 51 50 [2] 75 5e [2] 5e 72 [2] 70 50 [2] 64 4b [2] 6b 51 [2] 75 4c [2] 77 4d [2] 6c 4b [2] 70 4c [2] 6c 63 }

  condition:
    any of them
}