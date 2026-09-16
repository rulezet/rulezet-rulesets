rule TTP_XOR_QUAD_CurrentVersionRun_040a {
  strings:
    $key_040a = { 57 65 [2] 73 6b [2] 58 47 [2] 76 65 [2] 62 7e [2] 6d 64 [2] 73 79 [2] 71 78 [2] 6a 7e [2] 76 79 [2] 6a 56 }

  condition:
    any of them
}