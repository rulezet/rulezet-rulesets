rule TTP_XOR_QUAD_CurrentVersionRun_72fe {
  strings:
    $key_72fe = { 21 91 [2] 05 9f [2] 2e b3 [2] 00 91 [2] 14 8a [2] 1b 90 [2] 05 8d [2] 07 8c [2] 1c 8a [2] 00 8d [2] 1c a2 }

  condition:
    any of them
}