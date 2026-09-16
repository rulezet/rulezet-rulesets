rule TTP_XOR_QUAD_CurrentVersionRun_ebfc {
  strings:
    $key_ebfc = { b8 93 [2] 9c 9d [2] b7 b1 [2] 99 93 [2] 8d 88 [2] 82 92 [2] 9c 8f [2] 9e 8e [2] 85 88 [2] 99 8f [2] 85 a0 }

  condition:
    any of them
}