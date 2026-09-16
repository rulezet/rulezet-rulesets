rule TTP_XOR_QUAD_CurrentVersionRun_26fe {
  strings:
    $key_26fe = { 75 91 [2] 51 9f [2] 7a b3 [2] 54 91 [2] 40 8a [2] 4f 90 [2] 51 8d [2] 53 8c [2] 48 8a [2] 54 8d [2] 48 a2 }

  condition:
    any of them
}