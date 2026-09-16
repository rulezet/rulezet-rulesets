rule TTP_XOR_QUAD_CurrentVersionRun_e419 {
  strings:
    $key_e419 = { b7 76 [2] 93 78 [2] b8 54 [2] 96 76 [2] 82 6d [2] 8d 77 [2] 93 6a [2] 91 6b [2] 8a 6d [2] 96 6a [2] 8a 45 }

  condition:
    any of them
}