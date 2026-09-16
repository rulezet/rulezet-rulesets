rule TTP_XOR_QUAD_CurrentVersionRun_010f {
  strings:
    $key_010f = { 52 60 [2] 76 6e [2] 5d 42 [2] 73 60 [2] 67 7b [2] 68 61 [2] 76 7c [2] 74 7d [2] 6f 7b [2] 73 7c [2] 6f 53 }

  condition:
    any of them
}