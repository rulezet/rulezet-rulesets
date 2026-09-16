rule TTP_XOR_QUAD_CurrentVersionRun_541f {
  strings:
    $key_541f = { 07 70 [2] 23 7e [2] 08 52 [2] 26 70 [2] 32 6b [2] 3d 71 [2] 23 6c [2] 21 6d [2] 3a 6b [2] 26 6c [2] 3a 43 }

  condition:
    any of them
}