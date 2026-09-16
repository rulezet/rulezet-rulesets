rule TTP_XOR_QUAD_CurrentVersionRun_6a2f {
  strings:
    $key_6a2f = { 39 40 [2] 1d 4e [2] 36 62 [2] 18 40 [2] 0c 5b [2] 03 41 [2] 1d 5c [2] 1f 5d [2] 04 5b [2] 18 5c [2] 04 73 }

  condition:
    any of them
}