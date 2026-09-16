rule TTP_XOR_QUAD_CurrentVersionRun_f9ff {
  strings:
    $key_f9ff = { aa 90 [2] 8e 9e [2] a5 b2 [2] 8b 90 [2] 9f 8b [2] 90 91 [2] 8e 8c [2] 8c 8d [2] 97 8b [2] 8b 8c [2] 97 a3 }

  condition:
    any of them
}