rule TTP_XOR_QUAD_CurrentVersionRun_6225 {
  strings:
    $key_6225 = { 31 4a [2] 15 44 [2] 3e 68 [2] 10 4a [2] 04 51 [2] 0b 4b [2] 15 56 [2] 17 57 [2] 0c 51 [2] 10 56 [2] 0c 79 }

  condition:
    any of them
}