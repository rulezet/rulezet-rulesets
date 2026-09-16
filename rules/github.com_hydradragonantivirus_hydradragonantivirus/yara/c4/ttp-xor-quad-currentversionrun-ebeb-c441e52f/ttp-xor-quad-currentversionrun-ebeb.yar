rule TTP_XOR_QUAD_CurrentVersionRun_ebeb {
  strings:
    $key_ebeb = { b8 84 [2] 9c 8a [2] b7 a6 [2] 99 84 [2] 8d 9f [2] 82 85 [2] 9c 98 [2] 9e 99 [2] 85 9f [2] 99 98 [2] 85 b7 }

  condition:
    any of them
}