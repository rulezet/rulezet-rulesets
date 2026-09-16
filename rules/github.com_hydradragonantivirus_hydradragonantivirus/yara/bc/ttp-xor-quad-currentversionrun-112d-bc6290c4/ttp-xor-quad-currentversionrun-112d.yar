rule TTP_XOR_QUAD_CurrentVersionRun_112d {
  strings:
    $key_112d = { 42 42 [2] 66 4c [2] 4d 60 [2] 63 42 [2] 77 59 [2] 78 43 [2] 66 5e [2] 64 5f [2] 7f 59 [2] 63 5e [2] 7f 71 }

  condition:
    any of them
}