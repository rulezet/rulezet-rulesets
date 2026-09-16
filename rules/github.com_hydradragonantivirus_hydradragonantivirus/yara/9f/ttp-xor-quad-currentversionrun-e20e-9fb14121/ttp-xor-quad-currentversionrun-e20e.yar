rule TTP_XOR_QUAD_CurrentVersionRun_e20e {
  strings:
    $key_e20e = { b1 61 [2] 95 6f [2] be 43 [2] 90 61 [2] 84 7a [2] 8b 60 [2] 95 7d [2] 97 7c [2] 8c 7a [2] 90 7d [2] 8c 52 }

  condition:
    any of them
}