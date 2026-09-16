rule TTP_XOR_QUAD_CurrentVersionRun_213f {
  strings:
    $key_213f = { 72 50 [2] 56 5e [2] 7d 72 [2] 53 50 [2] 47 4b [2] 48 51 [2] 56 4c [2] 54 4d [2] 4f 4b [2] 53 4c [2] 4f 63 }

  condition:
    any of them
}