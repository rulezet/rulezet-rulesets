rule TTP_XOR_QUAD_CurrentVersionRun_401f {
  strings:
    $key_401f = { 13 70 [2] 37 7e [2] 1c 52 [2] 32 70 [2] 26 6b [2] 29 71 [2] 37 6c [2] 35 6d [2] 2e 6b [2] 32 6c [2] 2e 43 }

  condition:
    any of them
}