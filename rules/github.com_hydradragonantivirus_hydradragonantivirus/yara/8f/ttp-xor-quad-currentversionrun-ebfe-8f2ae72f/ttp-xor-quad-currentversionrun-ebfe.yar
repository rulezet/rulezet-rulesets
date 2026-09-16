rule TTP_XOR_QUAD_CurrentVersionRun_ebfe {
  strings:
    $key_ebfe = { b8 91 [2] 9c 9f [2] b7 b3 [2] 99 91 [2] 8d 8a [2] 82 90 [2] 9c 8d [2] 9e 8c [2] 85 8a [2] 99 8d [2] 85 a2 }

  condition:
    any of them
}