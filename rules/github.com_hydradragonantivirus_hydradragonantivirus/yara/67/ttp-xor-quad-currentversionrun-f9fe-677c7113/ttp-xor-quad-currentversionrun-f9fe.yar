rule TTP_XOR_QUAD_CurrentVersionRun_f9fe {
  strings:
    $key_f9fe = { aa 91 [2] 8e 9f [2] a5 b3 [2] 8b 91 [2] 9f 8a [2] 90 90 [2] 8e 8d [2] 8c 8c [2] 97 8a [2] 8b 8d [2] 97 a2 }

  condition:
    any of them
}