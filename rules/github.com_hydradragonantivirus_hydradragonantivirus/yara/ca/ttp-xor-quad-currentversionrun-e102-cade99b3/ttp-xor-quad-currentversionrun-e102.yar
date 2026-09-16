rule TTP_XOR_QUAD_CurrentVersionRun_e102 {
  strings:
    $key_e102 = { b2 6d [2] 96 63 [2] bd 4f [2] 93 6d [2] 87 76 [2] 88 6c [2] 96 71 [2] 94 70 [2] 8f 76 [2] 93 71 [2] 8f 5e }

  condition:
    any of them
}