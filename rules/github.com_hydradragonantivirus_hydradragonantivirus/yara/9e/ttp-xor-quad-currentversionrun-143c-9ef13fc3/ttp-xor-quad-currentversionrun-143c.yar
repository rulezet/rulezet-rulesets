rule TTP_XOR_QUAD_CurrentVersionRun_143c {
  strings:
    $key_143c = { 47 53 [2] 63 5d [2] 48 71 [2] 66 53 [2] 72 48 [2] 7d 52 [2] 63 4f [2] 61 4e [2] 7a 48 [2] 66 4f [2] 7a 60 }

  condition:
    any of them
}