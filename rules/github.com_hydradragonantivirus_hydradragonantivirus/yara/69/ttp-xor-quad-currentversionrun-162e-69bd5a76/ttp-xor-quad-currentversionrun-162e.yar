rule TTP_XOR_QUAD_CurrentVersionRun_162e {
  strings:
    $key_162e = { 45 41 [2] 61 4f [2] 4a 63 [2] 64 41 [2] 70 5a [2] 7f 40 [2] 61 5d [2] 63 5c [2] 78 5a [2] 64 5d [2] 78 72 }

  condition:
    any of them
}