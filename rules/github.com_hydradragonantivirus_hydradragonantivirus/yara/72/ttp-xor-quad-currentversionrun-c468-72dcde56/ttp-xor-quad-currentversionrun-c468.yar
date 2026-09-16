rule TTP_XOR_QUAD_CurrentVersionRun_c468 {
  strings:
    $key_c468 = { 97 07 [2] b3 09 [2] 98 25 [2] b6 07 [2] a2 1c [2] ad 06 [2] b3 1b [2] b1 1a [2] aa 1c [2] b6 1b [2] aa 34 }

  condition:
    any of them
}