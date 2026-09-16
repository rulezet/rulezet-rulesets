rule TTP_XOR_QUAD_CurrentVersionRun_fdfe {
  strings:
    $key_fdfe = { ae 91 [2] 8a 9f [2] a1 b3 [2] 8f 91 [2] 9b 8a [2] 94 90 [2] 8a 8d [2] 88 8c [2] 93 8a [2] 8f 8d [2] 93 a2 }

  condition:
    any of them
}