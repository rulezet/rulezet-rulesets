rule TTP_XOR_QUAD_CurrentVersionRun_2d0f {
  strings:
    $key_2d0f = { 7e 60 [2] 5a 6e [2] 71 42 [2] 5f 60 [2] 4b 7b [2] 44 61 [2] 5a 7c [2] 58 7d [2] 43 7b [2] 5f 7c [2] 43 53 }

  condition:
    any of them
}