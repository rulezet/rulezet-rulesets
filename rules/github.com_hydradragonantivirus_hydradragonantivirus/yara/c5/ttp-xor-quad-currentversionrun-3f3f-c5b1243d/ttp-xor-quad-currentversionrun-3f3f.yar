rule TTP_XOR_QUAD_CurrentVersionRun_3f3f {
  strings:
    $key_3f3f = { 6c 50 [2] 48 5e [2] 63 72 [2] 4d 50 [2] 59 4b [2] 56 51 [2] 48 4c [2] 4a 4d [2] 51 4b [2] 4d 4c [2] 51 63 }

  condition:
    any of them
}