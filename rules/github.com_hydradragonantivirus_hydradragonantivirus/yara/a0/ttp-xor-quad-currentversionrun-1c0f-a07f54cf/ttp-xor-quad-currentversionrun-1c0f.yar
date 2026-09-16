rule TTP_XOR_QUAD_CurrentVersionRun_1c0f {
  strings:
    $key_1c0f = { 4f 60 [2] 6b 6e [2] 40 42 [2] 6e 60 [2] 7a 7b [2] 75 61 [2] 6b 7c [2] 69 7d [2] 72 7b [2] 6e 7c [2] 72 53 }

  condition:
    any of them
}