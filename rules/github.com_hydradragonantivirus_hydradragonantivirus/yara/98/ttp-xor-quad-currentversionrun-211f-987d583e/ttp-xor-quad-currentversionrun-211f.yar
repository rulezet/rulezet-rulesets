rule TTP_XOR_QUAD_CurrentVersionRun_211f {
  strings:
    $key_211f = { 72 70 [2] 56 7e [2] 7d 52 [2] 53 70 [2] 47 6b [2] 48 71 [2] 56 6c [2] 54 6d [2] 4f 6b [2] 53 6c [2] 4f 43 }

  condition:
    any of them
}