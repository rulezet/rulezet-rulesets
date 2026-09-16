rule TTP_XOR_QUAD_CurrentVersionRun_e23e {
  strings:
    $key_e23e = { b1 51 [2] 95 5f [2] be 73 [2] 90 51 [2] 84 4a [2] 8b 50 [2] 95 4d [2] 97 4c [2] 8c 4a [2] 90 4d [2] 8c 62 }

  condition:
    any of them
}