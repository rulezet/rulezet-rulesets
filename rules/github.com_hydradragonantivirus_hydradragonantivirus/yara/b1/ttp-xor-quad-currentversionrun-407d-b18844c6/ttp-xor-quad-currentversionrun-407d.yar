rule TTP_XOR_QUAD_CurrentVersionRun_407d {
  strings:
    $key_407d = { 13 12 [2] 37 1c [2] 1c 30 [2] 32 12 [2] 26 09 [2] 29 13 [2] 37 0e [2] 35 0f [2] 2e 09 [2] 32 0e [2] 2e 21 }

  condition:
    any of them
}