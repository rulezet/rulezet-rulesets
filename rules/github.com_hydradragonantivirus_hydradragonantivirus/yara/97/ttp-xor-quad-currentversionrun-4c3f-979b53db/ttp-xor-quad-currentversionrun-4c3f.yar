rule TTP_XOR_QUAD_CurrentVersionRun_4c3f {
  strings:
    $key_4c3f = { 1f 50 [2] 3b 5e [2] 10 72 [2] 3e 50 [2] 2a 4b [2] 25 51 [2] 3b 4c [2] 39 4d [2] 22 4b [2] 3e 4c [2] 22 63 }

  condition:
    any of them
}