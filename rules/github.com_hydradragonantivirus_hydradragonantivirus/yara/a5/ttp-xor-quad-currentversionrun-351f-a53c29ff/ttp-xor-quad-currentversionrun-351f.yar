rule TTP_XOR_QUAD_CurrentVersionRun_351f {
  strings:
    $key_351f = { 66 70 [2] 42 7e [2] 69 52 [2] 47 70 [2] 53 6b [2] 5c 71 [2] 42 6c [2] 40 6d [2] 5b 6b [2] 47 6c [2] 5b 43 }

  condition:
    any of them
}