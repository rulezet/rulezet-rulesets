rule TTP_XOR_QUAD_CurrentVersionRun_6c3f {
  strings:
    $key_6c3f = { 3f 50 [2] 1b 5e [2] 30 72 [2] 1e 50 [2] 0a 4b [2] 05 51 [2] 1b 4c [2] 19 4d [2] 02 4b [2] 1e 4c [2] 02 63 }

  condition:
    any of them
}