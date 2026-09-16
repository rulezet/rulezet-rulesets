rule TTP_XOR_QUAD_CurrentVersionRun_3f7e {
  strings:
    $key_3f7e = { 6c 11 [2] 48 1f [2] 63 33 [2] 4d 11 [2] 59 0a [2] 56 10 [2] 48 0d [2] 4a 0c [2] 51 0a [2] 4d 0d [2] 51 22 }

  condition:
    any of them
}