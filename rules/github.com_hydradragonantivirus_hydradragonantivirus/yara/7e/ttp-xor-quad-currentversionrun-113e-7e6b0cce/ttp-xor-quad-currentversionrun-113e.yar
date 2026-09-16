rule TTP_XOR_QUAD_CurrentVersionRun_113e {
  strings:
    $key_113e = { 42 51 [2] 66 5f [2] 4d 73 [2] 63 51 [2] 77 4a [2] 78 50 [2] 66 4d [2] 64 4c [2] 7f 4a [2] 63 4d [2] 7f 62 }

  condition:
    any of them
}