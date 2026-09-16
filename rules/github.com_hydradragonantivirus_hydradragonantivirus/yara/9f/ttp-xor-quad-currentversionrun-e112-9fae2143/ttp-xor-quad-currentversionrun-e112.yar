rule TTP_XOR_QUAD_CurrentVersionRun_e112 {
  strings:
    $key_e112 = { b2 7d [2] 96 73 [2] bd 5f [2] 93 7d [2] 87 66 [2] 88 7c [2] 96 61 [2] 94 60 [2] 8f 66 [2] 93 61 [2] 8f 4e }

  condition:
    any of them
}