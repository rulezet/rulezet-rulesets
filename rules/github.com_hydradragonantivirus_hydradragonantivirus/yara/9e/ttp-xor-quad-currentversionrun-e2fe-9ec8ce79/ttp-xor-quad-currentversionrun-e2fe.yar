rule TTP_XOR_QUAD_CurrentVersionRun_e2fe {
  strings:
    $key_e2fe = { b1 91 [2] 95 9f [2] be b3 [2] 90 91 [2] 84 8a [2] 8b 90 [2] 95 8d [2] 97 8c [2] 8c 8a [2] 90 8d [2] 8c a2 }

  condition:
    any of them
}