rule TTP_XOR_QUAD_CurrentVersionRun_032f {
  strings:
    $key_032f = { 50 40 [2] 74 4e [2] 5f 62 [2] 71 40 [2] 65 5b [2] 6a 41 [2] 74 5c [2] 76 5d [2] 6d 5b [2] 71 5c [2] 6d 73 }

  condition:
    any of them
}