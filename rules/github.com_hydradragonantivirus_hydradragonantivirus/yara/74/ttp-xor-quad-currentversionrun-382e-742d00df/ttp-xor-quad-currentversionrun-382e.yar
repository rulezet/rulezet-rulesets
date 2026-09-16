rule TTP_XOR_QUAD_CurrentVersionRun_382e {
  strings:
    $key_382e = { 6b 41 [2] 4f 4f [2] 64 63 [2] 4a 41 [2] 5e 5a [2] 51 40 [2] 4f 5d [2] 4d 5c [2] 56 5a [2] 4a 5d [2] 56 72 }

  condition:
    any of them
}