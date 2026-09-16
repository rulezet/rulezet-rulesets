rule TTP_XOR_QUAD_CurrentVersionRun_fdea {
  strings:
    $key_fdea = { ae 85 [2] 8a 8b [2] a1 a7 [2] 8f 85 [2] 9b 9e [2] 94 84 [2] 8a 99 [2] 88 98 [2] 93 9e [2] 8f 99 [2] 93 b6 }

  condition:
    any of them
}