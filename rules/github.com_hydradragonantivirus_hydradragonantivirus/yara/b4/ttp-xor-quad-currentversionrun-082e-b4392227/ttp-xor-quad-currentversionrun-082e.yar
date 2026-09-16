rule TTP_XOR_QUAD_CurrentVersionRun_082e {
  strings:
    $key_082e = { 5b 41 [2] 7f 4f [2] 54 63 [2] 7a 41 [2] 6e 5a [2] 61 40 [2] 7f 5d [2] 7d 5c [2] 66 5a [2] 7a 5d [2] 66 72 }

  condition:
    any of them
}