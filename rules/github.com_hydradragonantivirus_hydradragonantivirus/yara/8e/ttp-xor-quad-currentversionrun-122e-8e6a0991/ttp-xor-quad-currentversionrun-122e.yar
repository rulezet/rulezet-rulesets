rule TTP_XOR_QUAD_CurrentVersionRun_122e {
  strings:
    $key_122e = { 41 41 [2] 65 4f [2] 4e 63 [2] 60 41 [2] 74 5a [2] 7b 40 [2] 65 5d [2] 67 5c [2] 7c 5a [2] 60 5d [2] 7c 72 }

  condition:
    any of them
}