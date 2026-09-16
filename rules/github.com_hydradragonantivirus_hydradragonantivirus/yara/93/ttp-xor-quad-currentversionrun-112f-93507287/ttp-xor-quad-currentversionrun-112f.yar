rule TTP_XOR_QUAD_CurrentVersionRun_112f {
  strings:
    $key_112f = { 42 40 [2] 66 4e [2] 4d 62 [2] 63 40 [2] 77 5b [2] 78 41 [2] 66 5c [2] 64 5d [2] 7f 5b [2] 63 5c [2] 7f 73 }

  condition:
    any of them
}