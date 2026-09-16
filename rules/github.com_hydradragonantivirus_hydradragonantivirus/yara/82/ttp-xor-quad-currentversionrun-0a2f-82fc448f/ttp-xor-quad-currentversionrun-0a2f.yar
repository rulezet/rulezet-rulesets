rule TTP_XOR_QUAD_CurrentVersionRun_0a2f {
  strings:
    $key_0a2f = { 59 40 [2] 7d 4e [2] 56 62 [2] 78 40 [2] 6c 5b [2] 63 41 [2] 7d 5c [2] 7f 5d [2] 64 5b [2] 78 5c [2] 64 73 }

  condition:
    any of them
}