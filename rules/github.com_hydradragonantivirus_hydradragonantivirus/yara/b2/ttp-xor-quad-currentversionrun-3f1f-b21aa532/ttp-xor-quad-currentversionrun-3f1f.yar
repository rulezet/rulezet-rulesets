rule TTP_XOR_QUAD_CurrentVersionRun_3f1f {
  strings:
    $key_3f1f = { 6c 70 [2] 48 7e [2] 63 52 [2] 4d 70 [2] 59 6b [2] 56 71 [2] 48 6c [2] 4a 6d [2] 51 6b [2] 4d 6c [2] 51 43 }

  condition:
    any of them
}