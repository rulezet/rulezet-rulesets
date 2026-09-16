rule TTP_XOR_QUAD_CurrentVersionRun_f91e {
  strings:
    $key_f91e = { aa 71 [2] 8e 7f [2] a5 53 [2] 8b 71 [2] 9f 6a [2] 90 70 [2] 8e 6d [2] 8c 6c [2] 97 6a [2] 8b 6d [2] 97 42 }

  condition:
    any of them
}