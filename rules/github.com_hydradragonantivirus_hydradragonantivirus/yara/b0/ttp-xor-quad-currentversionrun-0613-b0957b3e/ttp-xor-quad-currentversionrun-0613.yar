rule TTP_XOR_QUAD_CurrentVersionRun_0613 {
  strings:
    $key_0613 = { 55 7c [2] 71 72 [2] 5a 5e [2] 74 7c [2] 60 67 [2] 6f 7d [2] 71 60 [2] 73 61 [2] 68 67 [2] 74 60 [2] 68 4f }

  condition:
    any of them
}