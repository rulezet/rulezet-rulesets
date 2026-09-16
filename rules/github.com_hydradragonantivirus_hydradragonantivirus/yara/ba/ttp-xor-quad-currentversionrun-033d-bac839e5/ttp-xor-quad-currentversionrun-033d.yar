rule TTP_XOR_QUAD_CurrentVersionRun_033d {
  strings:
    $key_033d = { 50 52 [2] 74 5c [2] 5f 70 [2] 71 52 [2] 65 49 [2] 6a 53 [2] 74 4e [2] 76 4f [2] 6d 49 [2] 71 4e [2] 6d 61 }

  condition:
    any of them
}