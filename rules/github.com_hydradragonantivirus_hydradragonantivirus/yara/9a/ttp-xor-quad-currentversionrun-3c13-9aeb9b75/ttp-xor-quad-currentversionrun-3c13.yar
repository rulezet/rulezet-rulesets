rule TTP_XOR_QUAD_CurrentVersionRun_3c13 {
  strings:
    $key_3c13 = { 6f 7c [2] 4b 72 [2] 60 5e [2] 4e 7c [2] 5a 67 [2] 55 7d [2] 4b 60 [2] 49 61 [2] 52 67 [2] 4e 60 [2] 52 4f }

  condition:
    any of them
}