rule TTP_XOR_QUAD_CurrentVersionRun_141c {
  strings:
    $key_141c = { 47 73 [2] 63 7d [2] 48 51 [2] 66 73 [2] 72 68 [2] 7d 72 [2] 63 6f [2] 61 6e [2] 7a 68 [2] 66 6f [2] 7a 40 }

  condition:
    any of them
}