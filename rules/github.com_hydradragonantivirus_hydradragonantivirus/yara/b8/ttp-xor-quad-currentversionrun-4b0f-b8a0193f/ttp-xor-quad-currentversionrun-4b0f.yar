rule TTP_XOR_QUAD_CurrentVersionRun_4b0f {
  strings:
    $key_4b0f = { 18 60 [2] 3c 6e [2] 17 42 [2] 39 60 [2] 2d 7b [2] 22 61 [2] 3c 7c [2] 3e 7d [2] 25 7b [2] 39 7c [2] 25 53 }

  condition:
    any of them
}