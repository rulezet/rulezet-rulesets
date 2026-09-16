rule TTP_XOR_QUAD_CurrentVersionRun_030c {
  strings:
    $key_030c = { 50 63 [2] 74 6d [2] 5f 41 [2] 71 63 [2] 65 78 [2] 6a 62 [2] 74 7f [2] 76 7e [2] 6d 78 [2] 71 7f [2] 6d 50 }

  condition:
    any of them
}