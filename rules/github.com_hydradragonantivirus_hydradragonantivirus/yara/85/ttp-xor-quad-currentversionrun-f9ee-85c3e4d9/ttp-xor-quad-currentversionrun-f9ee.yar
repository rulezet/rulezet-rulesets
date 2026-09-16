rule TTP_XOR_QUAD_CurrentVersionRun_f9ee {
  strings:
    $key_f9ee = { aa 81 [2] 8e 8f [2] a5 a3 [2] 8b 81 [2] 9f 9a [2] 90 80 [2] 8e 9d [2] 8c 9c [2] 97 9a [2] 8b 9d [2] 97 b2 }

  condition:
    any of them
}