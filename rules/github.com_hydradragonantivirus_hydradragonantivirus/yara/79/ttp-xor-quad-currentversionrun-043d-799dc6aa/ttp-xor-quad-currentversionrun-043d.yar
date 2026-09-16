rule TTP_XOR_QUAD_CurrentVersionRun_043d {
  strings:
    $key_043d = { 57 52 [2] 73 5c [2] 58 70 [2] 76 52 [2] 62 49 [2] 6d 53 [2] 73 4e [2] 71 4f [2] 6a 49 [2] 76 4e [2] 6a 61 }

  condition:
    any of them
}