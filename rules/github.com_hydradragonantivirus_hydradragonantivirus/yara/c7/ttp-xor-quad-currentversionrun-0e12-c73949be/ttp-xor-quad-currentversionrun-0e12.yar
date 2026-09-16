rule TTP_XOR_QUAD_CurrentVersionRun_0e12 {
  strings:
    $key_0e12 = { 5d 7d [2] 79 73 [2] 52 5f [2] 7c 7d [2] 68 66 [2] 67 7c [2] 79 61 [2] 7b 60 [2] 60 66 [2] 7c 61 [2] 60 4e }

  condition:
    any of them
}