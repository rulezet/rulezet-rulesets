rule TTP_XOR_QUAD_CurrentVersionRun_7a2f {
  strings:
    $key_7a2f = { 29 40 [2] 0d 4e [2] 26 62 [2] 08 40 [2] 1c 5b [2] 13 41 [2] 0d 5c [2] 0f 5d [2] 14 5b [2] 08 5c [2] 14 73 }

  condition:
    any of them
}