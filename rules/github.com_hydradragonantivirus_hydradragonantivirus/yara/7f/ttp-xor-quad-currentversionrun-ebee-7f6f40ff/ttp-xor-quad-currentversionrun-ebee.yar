rule TTP_XOR_QUAD_CurrentVersionRun_ebee {
  strings:
    $key_ebee = { b8 81 [2] 9c 8f [2] b7 a3 [2] 99 81 [2] 8d 9a [2] 82 80 [2] 9c 9d [2] 9e 9c [2] 85 9a [2] 99 9d [2] 85 b2 }

  condition:
    any of them
}