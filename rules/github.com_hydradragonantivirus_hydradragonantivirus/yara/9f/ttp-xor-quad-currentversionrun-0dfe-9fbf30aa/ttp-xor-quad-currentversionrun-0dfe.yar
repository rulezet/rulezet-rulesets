rule TTP_XOR_QUAD_CurrentVersionRun_0dfe {
  strings:
    $key_0dfe = { 5e 91 [2] 7a 9f [2] 51 b3 [2] 7f 91 [2] 6b 8a [2] 64 90 [2] 7a 8d [2] 78 8c [2] 63 8a [2] 7f 8d [2] 63 a2 }

  condition:
    any of them
}