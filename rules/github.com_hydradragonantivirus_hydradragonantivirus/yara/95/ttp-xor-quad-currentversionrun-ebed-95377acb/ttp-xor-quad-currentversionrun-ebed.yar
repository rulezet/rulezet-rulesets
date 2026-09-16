rule TTP_XOR_QUAD_CurrentVersionRun_ebed {
  strings:
    $key_ebed = { b8 82 [2] 9c 8c [2] b7 a0 [2] 99 82 [2] 8d 99 [2] 82 83 [2] 9c 9e [2] 9e 9f [2] 85 99 [2] 99 9e [2] 85 b1 }

  condition:
    any of them
}