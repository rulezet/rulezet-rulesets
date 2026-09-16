rule TTP_XOR_QUAD_CurrentVersionRun_191f {
  strings:
    $key_191f = { 4a 70 [2] 6e 7e [2] 45 52 [2] 6b 70 [2] 7f 6b [2] 70 71 [2] 6e 6c [2] 6c 6d [2] 77 6b [2] 6b 6c [2] 77 43 }

  condition:
    any of them
}