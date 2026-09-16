rule TTP_XOR_QUAD_CurrentVersionRun_69fe {
  strings:
    $key_69fe = { 3a 91 [2] 1e 9f [2] 35 b3 [2] 1b 91 [2] 0f 8a [2] 00 90 [2] 1e 8d [2] 1c 8c [2] 07 8a [2] 1b 8d [2] 07 a2 }

  condition:
    any of them
}