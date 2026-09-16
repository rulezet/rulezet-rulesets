rule TTP_XOR_QUAD_CurrentVersionRun_243f {
  strings:
    $key_243f = { 77 50 [2] 53 5e [2] 78 72 [2] 56 50 [2] 42 4b [2] 4d 51 [2] 53 4c [2] 51 4d [2] 4a 4b [2] 56 4c [2] 4a 63 }

  condition:
    any of them
}