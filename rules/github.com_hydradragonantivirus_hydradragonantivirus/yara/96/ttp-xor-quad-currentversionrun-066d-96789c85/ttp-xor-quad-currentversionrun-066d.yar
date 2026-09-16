rule TTP_XOR_QUAD_CurrentVersionRun_066d {
  strings:
    $key_066d = { 55 02 [2] 71 0c [2] 5a 20 [2] 74 02 [2] 60 19 [2] 6f 03 [2] 71 1e [2] 73 1f [2] 68 19 [2] 74 1e [2] 68 31 }

  condition:
    any of them
}