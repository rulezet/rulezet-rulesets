rule TTP_XOR_QUAD_CurrentVersionRun_761f {
  strings:
    $key_761f = { 25 70 [2] 01 7e [2] 2a 52 [2] 04 70 [2] 10 6b [2] 1f 71 [2] 01 6c [2] 03 6d [2] 18 6b [2] 04 6c [2] 18 43 }

  condition:
    any of them
}