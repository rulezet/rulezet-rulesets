rule TTP_XOR_QUAD_CurrentVersionRun_0621 {
  strings:
    $key_0621 = { 55 4e [2] 71 40 [2] 5a 6c [2] 74 4e [2] 60 55 [2] 6f 4f [2] 71 52 [2] 73 53 [2] 68 55 [2] 74 52 [2] 68 7d }

  condition:
    any of them
}