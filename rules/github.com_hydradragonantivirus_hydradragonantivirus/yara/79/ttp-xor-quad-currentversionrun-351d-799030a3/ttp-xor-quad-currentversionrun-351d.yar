rule TTP_XOR_QUAD_CurrentVersionRun_351d {
  strings:
    $key_351d = { 66 72 [2] 42 7c [2] 69 50 [2] 47 72 [2] 53 69 [2] 5c 73 [2] 42 6e [2] 40 6f [2] 5b 69 [2] 47 6e [2] 5b 41 }

  condition:
    any of them
}