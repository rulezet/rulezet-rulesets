rule TTP_XOR_QUAD_CurrentVersionRun_021f {
  strings:
    $key_021f = { 51 70 [2] 75 7e [2] 5e 52 [2] 70 70 [2] 64 6b [2] 6b 71 [2] 75 6c [2] 77 6d [2] 6c 6b [2] 70 6c [2] 6c 43 }

  condition:
    any of them
}